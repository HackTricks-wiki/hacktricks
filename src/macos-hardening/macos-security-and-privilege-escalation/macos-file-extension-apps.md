# macOS File Extension और URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

यह macOS में installed सभी applications का एक database है, जिसे प्रत्येक installed application के बारे में जानकारी प्राप्त करने के लिए query किया जा सकता है, जैसे supported **URL schemes**, **document types**, **UTIs**, और default handlers।

इस database को निम्न command से dump करना संभव है:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) tool का उपयोग करके।

**`/usr/libexec/lsd`** database का brain है। यह **कई XPC services** प्रदान करता है, जैसे `.lsd.installation`, `.lsd.open`, `.lsd.openurl` और अन्य। लेकिन exposed XPC functionalities का उपयोग करने में सक्षम होने के लिए applications को कुछ **entitlements** की भी आवश्यकता होती है, जैसे MIME types या URL schemes के लिए default apps बदलने हेतु `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler` और अन्य।

**`/System/Library/CoreServices/launchservicesd`** service `com.apple.coreservices.launchservicesd` को claim करता है और running applications के बारे में information प्राप्त करने के लिए query किया जा सकता है। इसे system tool **`/usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) से query किया जा सकता है।

Operator के दृष्टिकोण से, ध्यान रखें कि आमतौर पर **दो उपयोगी views** होते हैं:

- LaunchServices / `lsd` द्वारा managed **registration database** (`.csstore` files द्वारा backed)।
- `LSHandlers` array के अंदर `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` में stored **per-user effective defaults**।

यह distinction महत्वपूर्ण है: कोई application किसी type या scheme को handle करने में सक्षम के रूप में **registered** हो सकता है, लेकिन **current default** फिर भी कोई अन्य bundle ID हो सकती है।

हाल के macOS releases में, registration discovery केवल `/Applications` तक सीमित नहीं है: अन्य Spotlight-visible, accessible folders और mounted/shared volumes में मौजूद apps भी registry में शामिल हो सकते हैं। इसलिए triage के दौरान `lsregister -dump` से प्राप्त `path` और volume information को सुरक्षित रखें और यह न मानें कि जब तक bundle discoverable है, तब तक किसी app को unregister करना स्थायी होगा।<sup>[[4]](#references)</sup>

## File Extension और URL scheme app handlers

निम्नलिखित line उन applications को खोजने में उपयोगी हो सकती है जो extension के आधार पर files खोल सकती हैं:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
या [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) जैसा कुछ उपयोग करें:
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
आप किसी application द्वारा supported extensions को इस तरह भी check कर सकते हैं:
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
## प्रभावी handlers की enumeration

**वर्तमान user के defaults** के लिए सबसे उपयोगी file आमतौर पर होती है:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
इससे **URL scheme** हैंडलर dump करने के लिए:
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
किसी sample file के UTI tree को resolve करने के लिए:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
यदि आप defaults को query करने या बदलने के लिए अधिक user-friendly CLI चाहते हैं:
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

Handler resolution में एक **file-specific** layer भी होती है। file के UTI और user के global default पर fallback करने से पहले, LaunchServices `com.apple.LaunchServices.OpenWith` extended attribute की जाँच करता है। Finder इसे तब बनाता है जब किसी एक file के लिए **Always Open With** चुना जाता है; इसका value एक binary property list होता है, जिसमें application path, bundle identifier और version selector शामिल होते हैं।<sup>[[3]](#references)</sup>

filename extension पर भरोसा किए बिना इसे inspect और decode करें:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
यह तब उपयोगी होता है जब `duti`, `dutix`, या `LSHandlers` किसी benign global default की सूचना देते हों, फिर भी एक single lure किसी अप्रत्याशित application के साथ खुलता हो। नियंत्रित lab के लिए, Finder के माध्यम से configured की गई file से exact opaque value कॉपी की जा सकती है; इसे delete करने से सामान्य type-based resolution restore हो जाता है:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## Interesting Info.plist keys

किसी application bundle की triage करते समय, ये keys सबसे अधिक महत्वपूर्ण होती हैं:

- **`CFBundleDocumentTypes`**: वे document groups जिन्हें bundle खोलने में सक्षम होने का दावा करता है।
- **`LSItemContentTypes`**: document types को UTIs से bind करने का **आधुनिक / preferred** तरीका।
- **`LSHandlerRank`**: LaunchServices द्वारा उपयोग की जाने वाली ranking (`Owner`, `Default`, `Alternate`, `None`)।
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: app द्वारा implemented custom URI schemes।
- **`UTExportedTypeDeclarations`**: वे UTIs जिनका app **मालिक** है।
- **`UTImportedTypeDeclarations`**: वे UTIs जिनका app मालिक नहीं है, लेकिन चाहता है कि system उन्हें recognize करे।

एक उपयोगी quick triage command है:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
एक सूक्ष्म लेकिन महत्वपूर्ण विवरण: यदि **`LSItemContentTypes`** मौजूद है, तो **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, और **`CFBundleTypeOSTypes`** जैसी पुरानी keys प्रभावी रूप से legacy compatibility data होती हैं। वास्तविक handler resolution के लिए पहले UTI path पर ध्यान दें।

## Offensive notes

Applications को interesting बनने के लिए execute करना आवश्यक नहीं है। किसी dropped या cloned `.app` bundle को **disk पर लिखे जाते ही `lsd` द्वारा automatically parse किया जा सकता है**, और इसके declared document types / URL schemes को user द्वारा bundle launch किए बिना ही register किया जा सकता है।

यह **persistence / hijacking research** और **initial-access chains**, दोनों के लिए उपयोगी है:

- कोई malicious app किसी **rare extension** या **custom UTI** का दावा कर सकता है और victim द्वारा lure file खोलने की प्रतीक्षा कर सकता है।
- कोई malicious app browser, Electron app, office document, chat client या किसी अन्य helper app से reachable **custom URL scheme** register कर सकता है।<sup>[[1]](#references)</sup>
- सामान्य default resolution को किसी particular candidate handler की testing से अलग रखने के लिए, scheme को LaunchServices के माध्यम से `open 'targetscheme://host/path?value=test'` से invoke करें, फिर किसी specific registered bundle को `open -b com.vendor.Target 'targetscheme://host/path?value=test'` से target करें। यह auditing के लिए उपयोगी है कि receiving app attacker-controlled URL components को किस प्रकार validate और decode करता है।<sup>[[1]](#references)</sup>
- यदि आप किसी app bundle को build करने के बाद edit करते हैं, तो इसे दोबारा parse करने के लिए LaunchServices को इस command से force कर सकते हैं:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
संदिग्ध bundles का परीक्षण करते समय इन पर विशेष ध्यान दें:

- असामान्य types पर **`LSHandlerRank=Owner`**।
- कई extensions का दावा करने वाले व्यापक **`CFBundleDocumentTypes`** arrays।
- **Helper / wrapper apps**, जिनका एकमात्र दिलचस्प behavior किसी document या URI handler के पीछे छिपा हो।
- **Shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`), जो अंततः LaunchServices में dispatch होती हैं। `.fileloc`-style tricks और संबंधित Gatekeeper angles के लिए [यह अन्य पेज](macos-security-protections/macos-fs-tricks/README.md) देखें।<sup>[[2]](#references)</sup>

यदि आपका लक्ष्य केवल किसी folder को browse करने या किसी file को select करने से passive code-execution प्राप्त करना है, तो [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) के dedicated page को भी देखें, क्योंकि यह एक अलग लेकिन closely related file-handler surface है।



## References

- [1] [Objective-See - Custom URL Schemes के माध्यम से Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: macOS पर Gatekeeper flaws पर एक closer look](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS सही app में file कैसे खोलता है](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia में LaunchServices को नियंत्रित करना](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}

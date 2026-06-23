# macOS फ़ाइल एक्सटेंशन & URL scheme ऐप handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

यह macOS में installed सभी applications का एक database है, जिसे query करके हर installed application की information प्राप्त की जा सकती है, जैसे supported **URL schemes**, **document types**, **UTIs**, और default handlers।

इस database को इस तरह dump किया जा सकता है:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) टूल का भी उपयोग कर सकते हैं।

**`/usr/libexec/lsd`** database का दिमाग है। यह **कई XPC services** प्रदान करता है जैसे `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, और भी बहुत कुछ। लेकिन इसे applications को exposed XPC functionalities का उपयोग करने देने के लिए कुछ **entitlements** की भी ज़रूरत होती है, जैसे MIME types या URL schemes के लिए default apps बदलने हेतु `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler`, और अन्य।

**`/System/Library/CoreServices/launchservicesd`** service `com.apple.coreservices.launchservicesd` को claim करता है और running applications के बारे में जानकारी पाने के लिए query किया जा सकता है। इसे system tool **`/usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) के साथ query किया जा सकता है।

operator perspective से, ध्यान रखें कि आमतौर पर **दो useful views** होते हैं:

- LaunchServices / `lsd` द्वारा managed **registration database** (जिसे `.csstore` files support करती हैं)।
- `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` में `LSHandlers` array के अंदर stored **per-user effective defaults**।

यह distinction महत्वपूर्ण है: कोई application किसी type या scheme को handle करने के लिए **registered** हो सकती है, लेकिन **current default** फिर भी कोई और bundle ID हो सकती है।

## File Extension & URL scheme app handlers

निम्न line extension के आधार पर files खोल सकने वाले applications को खोजने के लिए उपयोगी हो सकती है:
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
आप किसी application द्वारा supported extensions को भी इस तरह check कर सकते हैं:
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

**current user's defaults** के लिए सबसे उपयोगी file आमतौर पर होती है:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
इससे **URL scheme** handlers को dump करने के लिए:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** हैंडलर्स को dump करने के लिए:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
नमूना फ़ाइल के UTI tree को resolve करने के लिए:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
यदि आप defaults को query या change करने के लिए एक ज़्यादा friendly CLI चाहते हैं:
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
## Interesting Info.plist keys

किसी application bundle का triage करते समय, ये keys सबसे ज़्यादा महत्वपूर्ण होती हैं:

- **`CFBundleDocumentTypes`**: document groups जिन्हें bundle दावा करता है कि वह open कर सकता है।
- **`LSItemContentTypes`**: document types को UTIs से जोड़ने का **modern / preferred** तरीका।
- **`LSHandlerRank`**: LaunchServices द्वारा इस्तेमाल की जाने वाली ranking (`Owner`, `Default`, `Alternate`, `None`)।
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: app द्वारा implement किए गए custom URI schemes।
- **`UTExportedTypeDeclarations`**: UTIs जिन्हें app **own** करता है।
- **`UTImportedTypeDeclarations`**: UTIs जिन्हें app own नहीं करता लेकिन चाहता है कि system उन्हें recognize करे।

एक useful quick triage command है:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
एक सूक्ष्म लेकिन महत्वपूर्ण विवरण: यदि **`LSItemContentTypes`** मौजूद है, तो **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, और **`CFBundleTypeOSTypes`** जैसी पुरानी keys प्रभावी रूप से legacy compatibility data होती हैं। वास्तविक handler resolution के लिए, पहले UTI path पर ध्यान दें।

## Offensive notes

Applications को interesting बनने के लिए execute होना ज़रूरी नहीं है। एक dropped या cloned `.app` bundle को **जैसे ही वह disk पर लिखा जाता है, `lsd` द्वारा automatically parsed किया जा सकता है**, और उसके declared document types / URL schemes user के bundle launch किए बिना ही register हो सकते हैं।

यह **persistence / hijacking research** और **initial-access chains** दोनों के लिए उपयोगी है:

- एक malicious app एक **rare extension** या एक **custom UTI** claim कर सकता है और victim के lure file खोलने का इंतज़ार कर सकता है।
- एक malicious app browser, Electron app, office document, chat client, या किसी अन्य helper app से reachable एक **custom URL scheme** register कर सकता है।
- यदि आप build करने के बाद किसी app bundle को edit करते हैं, तो आप LaunchServices को इसे फिर से re-parse करने के लिए मजबूर कर सकते हैं:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
जब suspicious bundles का परीक्षण करें, तो इन पर खास ध्यान दें:

- **`LSHandlerRank=Owner`** uncommon types पर।
- **Broad `CFBundleDocumentTypes`** arrays जो कई extensions claim करते हैं।
- **Helper / wrapper apps** जिनका एकमात्र interesting behavior document या URI handler के पीछे होता है।
- **Shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`) जो आखिर में LaunchServices में dispatch हो जाते हैं। `.fileloc`-style tricks और related Gatekeeper angles के लिए, [this other page](macos-security-protections/macos-fs-tricks/README.md) देखें।

अगर आपका goal केवल folder browse करने या file select करने से passive code-execution है, तो [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) के dedicated page को भी देखें, क्योंकि यह अलग लेकिन closely related file-handler surface है।

## References

- **[Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)**
- **[Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)**
{{#include ../../banners/hacktricks-training.md}}

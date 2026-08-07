# macOS File Extension और URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

यह macOS में installed सभी applications का database है, जिसे प्रत्येक installed application के बारे में जानकारी प्राप्त करने के लिए query किया जा सकता है, जैसे supported **URL schemes**, **document types**, **UTIs**, और default handlers।

इस database को निम्नलिखित command से dump करना संभव है:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) tool का उपयोग करके।

**`/usr/libexec/lsd`** database का brain है। यह **several XPC services** जैसे `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, और अन्य services प्रदान करता है। लेकिन exposed XPC functionalities का उपयोग करने में सक्षम होने के लिए applications को कुछ **entitlements** की भी आवश्यकता होती है, जैसे MIME types या URL schemes के लिए default apps बदलने हेतु `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler`, और अन्य।

**`/System/Library/CoreServices/launchservicesd`** `com.apple.coreservices.launchservicesd` service को claim करता है और running applications के बारे में information प्राप्त करने के लिए query किया जा सकता है। इसे system tool **`/usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) के साथ query किया जा सकता है।

Operator के perspective से, ध्यान रखें कि आमतौर पर **दो useful views** होते हैं:

- LaunchServices / `lsd` द्वारा managed **registration database** (`.csstore` files द्वारा backed)।
- `LSHandlers` array के अंदर `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` में stored **per-user effective defaults**।

यह distinction महत्वपूर्ण है: कोई application किसी type या scheme को handle करने में सक्षम के रूप में **registered** हो सकता है, लेकिन **current default** फिर भी कोई अन्य bundle ID हो सकती है।

## File Extension और URL scheme app handlers

निम्नलिखित line उन applications को खोजने के लिए उपयोगी हो सकती है जो extension के आधार पर files खोल सकती हैं:
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
आप किसी application द्वारा समर्थित extensions की जाँच इस तरह भी कर सकते हैं:
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
## प्रभावी handlers की Enumeration

**वर्तमान user के defaults** के लिए सबसे उपयोगी file आमतौर पर होती है:
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
किसी sample file के UTI tree को resolve करने के लिए:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
यदि आप defaults को query या change करने के लिए अधिक user-friendly CLI चाहते हैं:
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
## महत्वपूर्ण Info.plist keys

किसी application bundle की triage करते समय, ये keys सबसे अधिक महत्वपूर्ण होती हैं:

- **`CFBundleDocumentTypes`**: वे document groups जिन्हें bundle open करने में सक्षम होने का दावा करता है।
- **`LSItemContentTypes`**: document types को UTIs से bind करने का **आधुनिक / preferred** तरीका।
- **`LSHandlerRank`**: LaunchServices द्वारा उपयोग की जाने वाली ranking (`Owner`, `Default`, `Alternate`, `None`)।
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: app द्वारा implemented custom URI schemes।
- **`UTExportedTypeDeclarations`**: वे UTIs जिनका **स्वामित्व app के पास है**।
- **`UTImportedTypeDeclarations`**: वे UTIs जिनका स्वामित्व app के पास नहीं है, लेकिन app चाहता है कि system उन्हें recognize करे।

एक उपयोगी quick triage command है:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
एक सूक्ष्म लेकिन महत्वपूर्ण विवरण: यदि **`LSItemContentTypes`** मौजूद है, तो **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, और **`CFBundleTypeOSTypes`** जैसी पुरानी keys प्रभावी रूप से legacy compatibility data हैं। वास्तविक handler resolution के लिए पहले UTI path पर ध्यान दें।

## Offensive notes

Applications को interesting बनने के लिए execute किया जाना आवश्यक नहीं है। किसी dropped या cloned `.app` bundle को **`lsd` द्वारा disk पर लिखे जाते ही automatically parse किया जा सकता है**, और इसके declared document types / URL schemes को user द्वारा bundle launch किए बिना भी register किया जा सकता है।

यह **persistence / hijacking research** और **initial-access chains**, दोनों के लिए उपयोगी है:

- कोई malicious app **rare extension** या **custom UTI** claim कर सकता है और victim के lure file खोलने की प्रतीक्षा कर सकता है।
- कोई malicious app browser, Electron app, office document, chat client या किसी अन्य helper app से reachable **custom URL scheme** register कर सकता है।<sup>[[1]](#references)</sup>
- यदि आप किसी app bundle को build करने के बाद edit करते हैं, तो आप LaunchServices को इसके साथ दोबारा parse करने के लिए force कर सकते हैं:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
संदिग्ध bundles का परीक्षण करते समय इन पर विशेष ध्यान दें:

- **`LSHandlerRank=Owner`** असामान्य types पर।
- कई extensions का दावा करने वाले विस्तृत **`CFBundleDocumentTypes`** arrays।
- **Helper / wrapper apps**, जिनका एकमात्र रोचक behavior document या URI handler के पीछे छिपा हो।
- **Shortcut-जैसी files** (`.webloc`, `.inetloc`, `.fileloc`), जो अंततः LaunchServices में dispatch होती हैं। `.fileloc`-style tricks और संबंधित Gatekeeper angles के लिए [this other page](macos-security-protections/macos-fs-tricks/README.md) देखें।<sup>[[2]](#references)</sup>

यदि आपका लक्ष्य केवल किसी folder को browse करने या file select करने से passive code-execution प्राप्त करना है, तो [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) के dedicated page को भी देखें, क्योंकि वह एक अलग, लेकिन closely related, file-handler surface है।

## References


- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}

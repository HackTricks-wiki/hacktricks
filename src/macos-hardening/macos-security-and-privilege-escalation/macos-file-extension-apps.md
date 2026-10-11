# macOS File Extension और URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

यह macOS में इंस्टॉल किए गए सभी applications का database है। इससे हर इंस्टॉल किए गए application की जानकारी, जैसे समर्थित **URL schemes**, **document types**, **UTIs** और default handlers, प्राप्त की जा सकती है।

इस database को इस कमांड से dump किया जा सकता है:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) टूल का उपयोग करके।

**`/usr/libexec/lsd`** डेटाबेस का मुख्य भाग है। यह `.lsd.installation`, `.lsd.open`, `.lsd.openurl` जैसी **कई XPC services** उपलब्ध कराता है। लेकिन उजागर XPC कार्यक्षमताओं का उपयोग करने के लिए एप्लिकेशनों को कुछ **entitlements** देना भी आवश्यक है, जैसे MIME types या URL schemes के लिए डिफ़ॉल्ट ऐप बदलने हेतु `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler` आदि।

**`/System/Library/CoreServices/launchservicesd`** `com.apple.coreservices.launchservicesd` सेवा का दावा करता है और चल रहे एप्लिकेशनों की जानकारी पाने के लिए इससे query की जा सकती है। इसे सिस्टम टूल **`/usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) से query किया जा सकता है।

ऑपरेटर के नज़रिए से, ध्यान रखें कि आम तौर पर **दो उपयोगी views** होते हैं:

- LaunchServices / `lsd` द्वारा प्रबंधित **registration database** (`.csstore` फ़ाइलों में संग्रहित)।
- `LSHandlers` array में मौजूद, `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` में संग्रहीत **प्रति-उपयोगकर्ता प्रभावी defaults**।

यह अंतर महत्वपूर्ण है: कोई एप्लिकेशन किसी type या scheme को संभालने के लिए **registered** हो सकता है, लेकिन **वर्तमान default** फिर भी कोई अन्य bundle ID हो सकता है।

हाल के macOS releases में, registration discovery केवल `/Applications` तक सीमित नहीं है: Spotlight में दिखने वाले और accessible अन्य folders तथा mounted/shared volumes के ऐप भी registry में शामिल हो सकते हैं। इसलिए triage के दौरान `lsregister -dump` से `path` और volume की जानकारी सुरक्षित रखें, और यह न मानें कि किसी ऐप को unregister करना स्थायी होगा, जब तक उसका bundle discoverable बना रहता है।<sup>[[4]](#references)</sup>

## File Extension और URL scheme app handlers

फ़ाइल extension के आधार पर कौन-से एप्लिकेशन फ़ाइलें खोल सकते हैं, यह पता लगाने के लिए निम्न पंक्ति उपयोगी हो सकती है:

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

आप किसी application द्वारा समर्थित extensions को इस तरह भी देख सकते हैं:

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

इससे **URL scheme** handlers dump करने के लिए:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

**content-type / UTI** handlers डंप करने के लिए:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

किसी sample file का UTI tree resolve करने के लिए:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

यदि आप defaults को query या बदलने के लिए ज़्यादा user-friendly CLI चाहते हैं:

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

### प्रति-फ़ाइल `Open With` ओवरराइड

हैंडलर रिज़ॉल्यूशन में **फ़ाइल-विशिष्ट** लेयर भी होती है। फ़ाइल के UTI और उपयोगकर्ता के ग्लोबल डिफ़ॉल्ट पर जाने से पहले, LaunchServices `com.apple.LaunchServices.OpenWith` extended attribute की जाँच करता है। Finder इसे तब बनाता है, जब किसी एक फ़ाइल के लिए **Always Open With** चुना जाता है; इसकी वैल्यू एक binary property list होती है, जिसमें application path, bundle identifier और version selector होता है।<sup>[[3]](#references)</sup>

फ़ाइल extension पर भरोसा किए बिना इसकी जाँच करें और इसे decode करें:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

यह तब उपयोगी होता है जब कोई एकल lure अप्रत्याशित application में खुलता है, जबकि `duti`, `dutix` या `LSHandlers` एक सुरक्षित global default की रिपोर्ट करते हैं। नियंत्रित lab के लिए, Finder के ज़रिए कॉन्फ़िगर की गई फ़ाइल से सटीक opaque value कॉपी की जा सकती है; इसे हटाने से सामान्य type-based resolution बहाल हो जाता है:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## Interesting Info.plist keys

किसी application bundle की प्रारंभिक जांच करते समय, ये keys सबसे ज़्यादा महत्वपूर्ण होती हैं:

- **`CFBundleDocumentTypes`**: वे document groups जिन्हें bundle खोलने का दावा करता है।
- **`LSItemContentTypes`**: document types को UTIs से जोड़ने का **आधुनिक / पसंदीदा** तरीका।
- **`LSHandlerRank`**: LaunchServices द्वारा इस्तेमाल की जाने वाली रैंकिंग (`Owner`, `Default`, `Alternate`, `None`)।
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: app द्वारा लागू की गई custom URI schemes।
- **`UTExportedTypeDeclarations`**: वे UTIs जिनका **स्वामित्व** app के पास है।
- **`UTImportedTypeDeclarations`**: वे UTIs जिनका स्वामित्व app के पास नहीं है, लेकिन app चाहता है कि system उन्हें पहचाने।

एक उपयोगी त्वरित जांच कमांड है:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

एक सूक्ष्म लेकिन महत्वपूर्ण बात: अगर **`LSItemContentTypes`** मौजूद है, तो **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`**, और **`CFBundleTypeOSTypes`** जैसी पुरानी keys प्रभावी रूप से legacy compatibility data होती हैं। वास्तविक handler resolution के लिए पहले UTI path पर ध्यान दें।

## Offensive notes

Applications को दिलचस्प बनने के लिए execute करना ज़रूरी नहीं है। किसी dropped या cloned `.app` bundle को disk पर लिखे जाते ही **`lsd` अपने-आप parse कर सकता है**, और उसके घोषित document types / URL schemes bundle को उपयोगकर्ता द्वारा launch किए बिना ही register हो सकते हैं।

यह **persistence / hijacking research** और **initial-access chains**—दोनों के लिए उपयोगी है:

- कोई malicious app **दुर्लभ extension** या **custom UTI** का दावा करके victim के lure file खोलने का इंतज़ार कर सकता है।
- कोई malicious app ऐसा **custom URL scheme** register कर सकता है, जिसे browser, Electron app, office document, chat client या कोई अन्य helper app खोल सके।<sup>[[1]](#references)</sup>
- सामान्य default resolution को किसी विशेष candidate handler की testing से अलग रखने के लिए, LaunchServices के ज़रिए scheme invoke करें: `open 'targetscheme://host/path?value=test'`; फिर किसी विशेष registered bundle को target करें: `open -b com.vendor.Target 'targetscheme://host/path?value=test'`। यह जाँचने में उपयोगी है कि receiving app attacker-controlled URL components को कैसे validate और decode करता है।<sup>[[1]](#references)</sup>
- अगर app bundle बनाने के बाद आप उसमें बदलाव करते हैं, तो LaunchServices को उसे दोबारा parse करने के लिए यह चलाएँ:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

संदिग्ध bundles की जाँच करते समय इन बातों पर खास ध्यान दें:

- असामान्य types पर **`LSHandlerRank=Owner`**।
- कई extensions का दावा करने वाले विस्तृत **`CFBundleDocumentTypes`** arrays।
- **Helper / wrapper apps**, जिनका एकमात्र दिलचस्प behavior किसी document या URI handler के पीछे छिपा हो।
- **Shortcut जैसी files** (`.webloc`, `.inetloc`, `.fileloc`), जो अंततः LaunchServices में dispatch होती हैं। `.fileloc`-style tricks और उनसे जुड़े Gatekeeper पहलुओं के लिए [यह दूसरा पेज](macos-security-protections/macos-fs-tricks/README.md) देखें।<sup>[[2]](#references)</sup>

अगर आपका लक्ष्य किसी folder को बस browse करने या file select करने भर से passive code-execution करना है, तो [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) के लिए समर्पित पेज भी देखें, क्योंकि यह file-handler का एक अलग, लेकिन इससे closely related surface है।



## References

- [1] [Objective-See - Custom URL Schemes के ज़रिए Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate को bypass करना: macOS पर Gatekeeper की खामियों पर एक नज़दीकी नज़र](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS किसी file को सही app में कैसे खोलता है](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia में LaunchServices को नियंत्रित करना](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}

# macOS फ़ाइल एक्सटेंशन और URL स्कीम ऐप हैंडलर

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices डेटाबेस

यह macOS में सभी स्थापित अनुप्रयोगों का एक डेटाबेस है जिसे प्रत्येक स्थापित अनुप्रयोग के बारे में जानकारी प्राप्त करने के लिए क्वेरी किया जा सकता है जैसे कि यह किस URL स्कीम का समर्थन करता है और MIME प्रकार। 

इस डेटाबेस को डंप करना संभव है:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
या उपकरण का उपयोग करके [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html)।

**`/usr/libexec/lsd`** डेटाबेस का मस्तिष्क है। यह **कई XPC सेवाएँ** प्रदान करता है जैसे कि `.lsd.installation`, `.lsd.open`, `.lsd.openurl`, और अधिक। लेकिन इसे एक्सपोज़ किए गए XPC कार्यक्षमताओं का उपयोग करने के लिए अनुप्रयोगों के लिए **कुछ अधिकारों** की आवश्यकता होती है, जैसे कि `.launchservices.changedefaulthandler` या `.launchservices.changeurlschemehandler` ताकि MIME प्रकारों या URL स्कीमों के लिए डिफ़ॉल्ट ऐप्स को बदल सकें और अन्य।

**`/System/Library/CoreServices/launchservicesd`** सेवा `com.apple.coreservices.launchservicesd` का दावा करता है और चल रहे अनुप्रयोगों के बारे में जानकारी प्राप्त करने के लिए क्वेरी किया जा सकता है। इसे सिस्टम उपकरण /**`usr/bin/lsappinfo`** या [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) के साथ क्वेरी किया जा सकता है।

## फ़ाइल एक्सटेंशन और URL स्कीम ऐप हैंडलर

निम्नलिखित पंक्ति उन अनुप्रयोगों को खोजने के लिए उपयोगी हो सकती है जो एक्सटेंशन के आधार पर फ़ाइलें खोल सकते हैं:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
या कुछ ऐसा उपयोग करें जैसे [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps):
```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```
आप एक एप्लिकेशन द्वारा समर्थित एक्सटेंशन भी चेक कर सकते हैं:
```
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
{{#include ../../banners/hacktricks-training.md}}

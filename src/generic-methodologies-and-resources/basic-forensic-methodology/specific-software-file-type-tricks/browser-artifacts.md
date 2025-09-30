# ब्राउज़र आर्टिफैक्ट्स

{{#include ../../../banners/hacktricks-training.md}}

## ब्राउज़र आर्टिफैक्ट्स <a href="#id-3def" id="id-3def"></a>

ब्राउज़र आर्टिफैक्ट्स में वे विभिन्न प्रकार के डेटा शामिल होते हैं जिन्हें वेब ब्राउज़र द्वारा स्टोर किया जाता है, जैसे नेविगेशन इतिहास, बुकमार्क और कैश डेटा। ये आर्टिफैक्ट्स ऑपरेटिंग सिस्टम के अंदर विशिष्ट फोल्डरों में रखे जाते हैं, ब्राउज़र के अनुसार स्थान और नाम अलग हो सकते हैं, पर सामान्य रूप से समान प्रकार के डेटा स्टोर होते हैं।

यहाँ सबसे सामान्य ब्राउज़र आर्टिफैक्ट्स का सारांश दिया गया है:

- **Navigation History**: वेबसाइटों पर उपयोगकर्ता की विज़िट्स को ट्रैक करता है, जो खतरनाक साइटों की विज़िट्स की पहचान करने में उपयोगी है।
- **Autocomplete Data**: बार-बार की गई खोजों के आधार पर सुझाव देता है; नेविगेशन इतिहास के साथ मिलकर उपयोगी जानकारी प्रदान करता है।
- **Bookmarks**: उपयोगकर्ता द्वारा तेज़ी से एक्सेस के लिए सेव किए गए साइट्स।
- **Extensions and Add-ons**: ब्राउज़र एक्सटेंशन या ऐड-ऑन जो उपयोगकर्ता ने इंस्टॉल किए हों।
- **Cache**: वेब सामग्री (जैसे इमेज, JavaScript फ़ाइलें) स्टोर करता है ताकि वेबसाइट लोडिंग समय बेहतर हो; फॉरेंसिक विश्लेषण के लिए मूल्यवान होता है।
- **Logins**: संग्रहीत लॉगिन क्रेडेंशियल।
- **Favicons**: वेबसाइट्स से जुड़ी आइकॉन जो टैब और बुकमार्क में दिखाई देती हैं; उपयोगकर्ता विज़िट्स पर अतिरिक्त जानकारी देने में सहायक।
- **Browser Sessions**: खुली ब्राउज़र सत्रों से संबंधित डेटा।
- **Downloads**: ब्राउज़र के माध्यम से डाउनलोड की गई फ़ाइलों के रिकॉर्ड।
- **Form Data**: वेब फॉर्म्स में डाली गई जानकारी, भविष्य में ऑटोफिल सुझावों के लिए सेव की जाती है।
- **Thumbnails**: वेबसाइटों की प्रीव्यू इमेजेस।
- **Custom Dictionary.txt**: ब्राउज़र की डिक्शनरी में उपयोगकर्ता द्वारा जोड़े गए शब्द।

## Firefox

Firefox यूज़र डेटा को प्रोफाइल्स में व्यवस्थित करता है, जो ऑपरेटिंग सिस्टम के आधार पर विशिष्ट स्थानों में स्टोर होते हैं:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

इन डायरेक्टरीज़ के भीतर `profiles.ini` फ़ाइल यूज़र प्रोफाइल्स की सूची देती है। प्रत्येक प्रोफ़ाइल का डेटा उसी डायरेक्टरी में `profiles.ini` में `Path` वेरिएबल में नामित फ़ोल्डर में स्टोर होता है। अगर किसी प्रोफ़ाइल का फ़ोल्डर गायब है, तो संभवतः उसे डिलीट कर दिया गया होगा।

प्रत्येक प्रोफ़ाइल फ़ोल्डर के भीतर, आप कई महत्वपूर्ण फ़ाइलें पा सकते हैं:

- **places.sqlite**: इतिहास, बुकमार्क और डाउनलोड स्टोर करता है। Windows पर इतिहास डेटा एक्सेस करने के लिए [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) जैसे टूल्स उपलब्ध हैं।
- इतिहास और डाउनलोड जानकारी निकालने के लिए विशिष्ट SQL क्वेरीज का उपयोग करें।
- **bookmarkbackups**: बुकमार्क्स के बैकअप समाहित करता है।
- **formhistory.sqlite**: वेब फॉर्म डेटा स्टोर करता है।
- **handlers.json**: प्रोटोकॉल हैंडलर्स का प्रबंधन करता है।
- **persdict.dat**: कस्टम डिक्शनरी शब्द।
- **addons.json** और **extensions.sqlite**: इंस्टॉल किए गए ऐड-ऑन और एक्सटेंशन्स की जानकारी।
- **cookies.sqlite**: कुकीज़ स्टोर करता है; Windows पर निरीक्षण के लिए [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) उपलब्ध है।
- **cache2/entries** या **startupCache**: कैश डेटा, जिन्हें [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) जैसे टूल्स के जरिए एक्सेस किया जा सकता है।
- **favicons.sqlite**: favicons स्टोर करता है।
- **prefs.js**: यूज़र सेटिंग्स और प्राथमिकताएँ।
- **downloads.sqlite**: पुराने डाउनलोड डेटाबेस; अब places.sqlite में एकीकृत।
- **thumbnails**: वेबसाइट थंबनेल।
- **logins.json**: एन्क्रिप्टेड लॉगिन जानकारी।
- **key4.db** या **key3.db**: संवेदनशील जानकारी को सुरक्षित रखने के लिए एन्क्रिप्शन कीज़ स्टोर करता है।

इसके अलावा, ब्राउज़र के anti-phishing सेटिंग्स की जाँच `prefs.js` में `browser.safebrowsing` एंट्रीज़ को खोजकर की जा सकती है, जो दर्शाती हैं कि safe browsing फीचर सक्षम है या अक्षम।

To try to decrypt the master password, you can use [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt)\
निम्न स्क्रिप्ट और कॉल के साथ आप ब्रूट फोर्स के लिए एक पासवर्ड फ़ाइल निर्दिष्ट कर सकते हैं:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (692).png>)

## Google Chrome

Google Chrome ऑपरेटिंग सिस्टम के आधार पर उपयोगकर्ता प्रोफाइल निम्न स्थानों में संग्रहीत करता है:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

इन निर्देशिकाओं के भीतर अधिकांश उपयोगकर्ता डेटा **Default/** या **ChromeDefaultData/** फ़ोल्डरों में मिल सकता है। निम्नलिखित फ़ाइलों में महत्वपूर्ण डेटा होता है:

- **History**: URLs, downloads, और search keywords होते हैं। Windows पर इतिहास पढ़ने के लिए [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) का उपयोग किया जा सकता है। "Transition Type" कॉलम के विभिन्न अर्थ होते हैं, जैसे यूज़र द्वारा लिंक पर क्लिक, टाइप किए गए URLs, form submissions, और page reloads।
- **Cookies**: Cookies संग्रहीत करता है। निरीक्षण के लिए [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) उपलब्ध है।
- **Cache**: Cached डेटा रखता है। निरीक्षण के लिए Windows उपयोगकर्ता [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) का उपयोग कर सकते हैं।

Electron-based desktop apps (e.g., Discord) भी Chromium Simple Cache का उपयोग करते हैं और डिस्क पर समृद्ध artifacts छोड़ते हैं। देखें:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: उपयोगकर्ता के bookmarks।
- **Web Data**: form history शामिल है।
- **Favicons**: वेबसाइट favicons संग्रहीत करता है।
- **Login Data**: उपयोगकर्ता नाम और पासवर्ड जैसी लॉगिन क्रेडेंशियल्स शामिल हैं।
- **Current Session**/**Current Tabs**: वर्तमान browsing session और खुली tabs का डेटा।
- **Last Session**/**Last Tabs**: Chrome बंद होने से पहले अंतिम session के दौरान सक्रिय साइट्स की जानकारी।
- **Extensions**: ब्राउज़र extensions और addons के डायरेक्टरी।
- **Thumbnails**: वेबसाइट thumbnails संग्रहीत करता है।
- **Preferences**: एक जानकारीपूर्ण फ़ाइल, जिसमें plugins, extensions, pop-ups, notifications और अन्य सेटिंग्स शामिल होती हैं।
- **Browser’s built-in anti-phishing**: यह जाँचने के लिए कि anti-phishing और malware protection सक्षम हैं या नहीं, चलाएँ `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences`। आउटपुट में `{"enabled: true,"}` देखें।

## **SQLite DB Data Recovery**

जैसा कि पिछली सेक्शन में दिखाया गया है, Chrome और Firefox दोनों डेटा संग्रहीत करने के लिए **SQLite** डेटाबेस का उपयोग करते हैं। हटाई गई प्रविष्टियों को **recover** करना संभव है, इसके लिए टूल [**sqlparse**](https://github.com/padfoot999/sqlparse) या [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) का उपयोग किया जा सकता है।

## **Internet Explorer 11**

Internet Explorer 11 अपना डेटा और मेटाडेटा विभिन्न स्थानों पर प्रबंधित करता है, जिससे संग्रहीत जानकारी और उसके संबंधित विवरणों को अलग करना और एक्सेस/प्रबंधित करना आसान होता है।

### Metadata Storage

Internet Explorer के मेटाडेटा `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` में संग्रहीत होते हैं (जहाँ VX V01, V16, या V24 हो सकता है)। इसके साथ `V01.log` फ़ाइल में `WebcacheVX.data` से modification time असंगतियाँ दिख सकती हैं, जिसे सुधारने के लिए `esentutl /r V01 /d` की आवश्यकता हो सकती है। यह मेटाडेटा एक ESE database में होता है, जिसे photorec जैसे टूल से recover किया जा सकता है और [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) से निरीक्षण किया जा सकता है। **Containers** टेबल के भीतर यह पता लगाया जा सकता है कि प्रत्येक डेटा सेगमेंट किस तालिका या container में संग्रहीत है, जिसमें Skype जैसे अन्य Microsoft टूल्स के cache विवरण भी शामिल हैं।

### Cache Inspection

cache निरीक्षण के लिए [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) टूल उपलब्ध है, जिसे cache डेटा extraction फ़ोल्डर का स्थान देना आवश्यक होता है। cache के मेटाडेटा में filename, directory, access count, URL origin, और cache निर्माण, access, modification, और expiry समय के timestamps शामिल होते हैं।

### Cookies Management

Cookies को [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) से एक्सप्लोर किया जा सकता है, जिसमें मेटाडेटा में नाम, URLs, access counts, और विभिन्न समय-संबंधी विवरण होते हैं। Persistent cookies `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` में संग्रहीत होते हैं, जबकि session cookies मेमोरी में रहते हैं।

### Download Details

Downloads का मेटाडेटा [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) से एक्सेस किया जा सकता है, और विशिष्ट containers में URL, file type, और download location जैसे डेटा होते हैं। फ़िजिकल फ़ाइलें `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` के तहत मिल सकती हैं।

### Browsing History

Browsing history देखने के लिए [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) का उपयोग किया जा सकता है, इसके लिए extracted history फ़ाइलों का स्थान और Internet Explorer के लिए कॉन्फ़िगरेशन आवश्यक है। यहां मेटाडेटा में modification और access times के साथ access counts भी शामिल होते हैं। History फ़ाइलें `%userprofile%\Appdata\Local\Microsoft\Windows\History` में स्थित होती हैं।

### Typed URLs

Typed URLs और उनके उपयोग समय NTUSER.DAT के रजिस्ट्री में `Software\Microsoft\InternetExplorer\TypedURLs` और `Software\Microsoft\InternetExplorer\TypedURLsTime` में संग्रहीत होते हैं, जो उपयोगकर्ता द्वारा दर्ज किए गए अंतिम 50 URLs और उनकी अंतिम प्रविष्टि समय को ट्रैक करते हैं।

## Microsoft Edge

Microsoft Edge उपयोगकर्ता डेटा `%userprofile%\Appdata\Local\Packages` में संग्रहीत करता है। विभिन्न डेटा प्रकारों के पाथ्स:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari डेटा `/Users/$User/Library/Safari` पर संग्रहीत होता है। प्रमुख फ़ाइलें:

- **History.db**: `history_visits` और `history_items` तालिकाएँ जिनमें URLs और visit timestamps होते हैं। query करने के लिए `sqlite3` का उपयोग करें।
- **Downloads.plist**: डाउनलोड की गई फ़ाइलों की जानकारी।
- **Bookmarks.plist**: bookmarked URLs संग्रहीत करता है।
- **TopSites.plist**: सबसे अधिक देखी गई साइट्स।
- **Extensions.plist**: Safari browser extensions की सूची। पुनःप्राप्त करने के लिए `plutil` या `pluginkit` का उपयोग करें।
- **UserNotificationPermissions.plist**: उन डोमेनों की सूची जिन्हें notifications करने की अनुमति दी गई है। पार्स करने के लिए `plutil` का उपयोग करें।
- **LastSession.plist**: अंतिम सत्र की tabs। पार्स करने के लिए `plutil` का उपयोग करें।
- **Browser’s built-in anti-phishing**: जांच करने के लिए `defaults read com.apple.Safari WarnAboutFraudulentWebsites` चलाएँ। उत्तर 1 होने पर यह फीचर सक्रिय है।

## Opera

Opera का डेटा `/Users/$USER/Library/Application Support/com.operasoftware.Opera` में स्थित होता है और history व downloads के लिए Chrome के फॉर्मेट को साझा करता है।

- **Browser’s built-in anti-phishing**: जाँचने के लिए Preferences फ़ाइल में `fraud_protection_enabled` को grep करके देखें कि क्या यह `true` पर सेट है।

ये paths और commands विभिन्न वेब ब्राउज़र्स द्वारा संग्रहीत ब्राउज़िंग डेटा तक पहुँचने और उसे समझने के लिए निर्णायक हैं।

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}

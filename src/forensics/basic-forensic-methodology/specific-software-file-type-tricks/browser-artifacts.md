# ब्राउज़र आर्टिफैक्ट्स

{{#include ../../../banners/hacktricks-training.md}}

## ब्राउज़र आर्टिफैक्ट्स <a href="#id-3def" id="id-3def"></a>

ब्राउज़र आर्टिफैक्ट्स में विभिन्न प्रकार के डेटा शामिल होते हैं जो वेब ब्राउज़रों द्वारा संग्रहीत किए जाते हैं, जैसे कि नेविगेशन इतिहास, बुकमार्क और कैश डेटा। ये आर्टिफैक्ट्स ऑपरेटिंग सिस्टम के भीतर विशिष्ट फ़ोल्डरों में रखे जाते हैं, जो ब्राउज़रों के बीच स्थान और नाम में भिन्न होते हैं, फिर भी सामान्यतः समान डेटा प्रकारों को संग्रहीत करते हैं।

यहाँ सबसे सामान्य ब्राउज़र आर्टिफैक्ट्स का सारांश है:

- **नेविगेशन इतिहास**: उपयोगकर्ता द्वारा वेबसाइटों पर किए गए दौरे को ट्रैक करता है, जो दुर्भावनापूर्ण साइटों पर दौरे की पहचान करने के लिए उपयोगी है।
- **ऑटो-कंप्लीट डेटा**: बार-बार किए गए खोजों के आधार पर सुझाव, जो नेविगेशन इतिहास के साथ मिलकर अंतर्दृष्टि प्रदान करते हैं।
- **बुकमार्क्स**: उपयोगकर्ता द्वारा त्वरित पहुँच के लिए सहेजे गए साइटें।
- **एक्सटेंशन और ऐड-ऑन**: उपयोगकर्ता द्वारा स्थापित ब्राउज़र एक्सटेंशन या ऐड-ऑन।
- **कैश**: वेब सामग्री (जैसे, चित्र, जावास्क्रिप्ट फ़ाइलें) को संग्रहीत करता है ताकि वेबसाइट लोडिंग समय में सुधार हो सके, फोरेंसिक विश्लेषण के लिए मूल्यवान।
- **लॉगिन**: संग्रहीत लॉगिन क्रेडेंशियल्स।
- **फेविकॉन**: वेबसाइटों से जुड़े आइकन, जो टैब और बुकमार्क में दिखाई देते हैं, उपयोगकर्ता दौरे पर अतिरिक्त जानकारी के लिए उपयोगी।
- **ब्राउज़र सत्र**: खुले ब्राउज़र सत्रों से संबंधित डेटा।
- **डाउनलोड**: ब्राउज़र के माध्यम से डाउनलोड की गई फ़ाइलों का रिकॉर्ड।
- **फॉर्म डेटा**: वेब फॉर्म में दर्ज की गई जानकारी, भविष्य के ऑटोफिल सुझावों के लिए सहेजी गई।
- **थंबनेल्स**: वेबसाइटों के पूर्वावलोकन चित्र।
- **कस्टम डिक्शनरी.txt**: शब्द जो उपयोगकर्ता द्वारा ब्राउज़र के डिक्शनरी में जोड़े गए।

## फ़ायरफ़ॉक्स

फ़ायरफ़ॉक्स उपयोगकर्ता डेटा को प्रोफाइल में व्यवस्थित करता है, जो ऑपरेटिंग सिस्टम के आधार पर विशिष्ट स्थानों में संग्रहीत होते हैं:

- **लिनक्स**: `~/.mozilla/firefox/`
- **मैकओएस**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **विंडोज**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

इन निर्देशिकाओं में एक `profiles.ini` फ़ाइल उपयोगकर्ता प्रोफाइल की सूची बनाती है। प्रत्येक प्रोफाइल का डेटा `profiles.ini` में `Path` वेरिएबल में नामित फ़ोल्डर में संग्रहीत होता है, जो `profiles.ini` के समान निर्देशिका में स्थित होता है। यदि किसी प्रोफाइल का फ़ोल्डर गायब है, तो इसे हटाया जा सकता है।

प्रोफाइल फ़ोल्डर के भीतर, आप कई महत्वपूर्ण फ़ाइलें पा सकते हैं:

- **places.sqlite**: इतिहास, बुकमार्क और डाउनलोड संग्रहीत करता है। विंडोज़ पर [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) जैसे उपकरण इतिहास डेटा तक पहुँच सकते हैं।
- इतिहास और डाउनलोड जानकारी निकालने के लिए विशिष्ट SQL क्वेरी का उपयोग करें।
- **bookmarkbackups**: बुकमार्क के बैकअप को शामिल करता है।
- **formhistory.sqlite**: वेब फॉर्म डेटा संग्रहीत करता है।
- **handlers.json**: प्रोटोकॉल हैंडलर्स का प्रबंधन करता है।
- **persdict.dat**: कस्टम डिक्शनरी शब्द।
- **addons.json** और **extensions.sqlite**: स्थापित ऐड-ऑन और एक्सटेंशन की जानकारी।
- **cookies.sqlite**: कुकी संग्रहण, विंडोज़ पर निरीक्षण के लिए [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) उपलब्ध है।
- **cache2/entries** या **startupCache**: कैश डेटा, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) जैसे उपकरणों के माध्यम से पहुँच योग्य।
- **favicons.sqlite**: फेविकॉन संग्रहीत करता है।
- **prefs.js**: उपयोगकर्ता सेटिंग्स और प्राथमिकताएँ।
- **downloads.sqlite**: पुरानी डाउनलोड डेटाबेस, अब places.sqlite में एकीकृत।
- **thumbnails**: वेबसाइट थंबनेल्स।
- **logins.json**: एन्क्रिप्टेड लॉगिन जानकारी।
- **key4.db** या **key3.db**: संवेदनशील जानकारी को सुरक्षित करने के लिए एन्क्रिप्शन कुंजी संग्रहीत करता है।

अतिरिक्त रूप से, ब्राउज़र के एंटी-फिशिंग सेटिंग्स की जांच `prefs.js` में `browser.safebrowsing` प्रविष्टियों की खोज करके की जा सकती है, जो यह संकेत करती है कि सुरक्षित ब्राउज़िंग सुविधाएँ सक्षम या अक्षम हैं।

मास्टर पासवर्ड को डिक्रिप्ट करने के लिए, आप [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) का उपयोग कर सकते हैं\
इस स्क्रिप्ट और कॉल के साथ आप एक पासवर्ड फ़ाइल को ब्रूट फोर्स करने के लिए निर्दिष्ट कर सकते हैं:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![](<../../../images/image (417).png>)

## Google Chrome

Google Chrome उपयोगकर्ता प्रोफाइल को ऑपरेटिंग सिस्टम के आधार पर विशिष्ट स्थानों में संग्रहीत करता है:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

इन निर्देशिकाओं के भीतर, अधिकांश उपयोगकर्ता डेटा **Default/** या **ChromeDefaultData/** फ़ोल्डरों में पाया जा सकता है। निम्नलिखित फ़ाइलें महत्वपूर्ण डेटा रखती हैं:

- **History**: URLs, डाउनलोड और खोज कीवर्ड शामिल हैं। Windows पर, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) का उपयोग इतिहास पढ़ने के लिए किया जा सकता है। "Transition Type" कॉलम में विभिन्न अर्थ होते हैं, जिसमें उपयोगकर्ता द्वारा लिंक पर क्लिक करना, टाइप किए गए URLs, फ़ॉर्म सबमिशन और पृष्ठ पुनः लोड करना शामिल है।
- **Cookies**: कुकीज़ संग्रहीत करता है। निरीक्षण के लिए, [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) उपलब्ध है।
- **Cache**: कैश डेटा रखता है। निरीक्षण के लिए, Windows उपयोगकर्ता [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) का उपयोग कर सकते हैं।
- **Bookmarks**: उपयोगकर्ता बुकमार्क।
- **Web Data**: फ़ॉर्म इतिहास शामिल है।
- **Favicons**: वेबसाइट के फ़ेविकॉन संग्रहीत करता है।
- **Login Data**: उपयोगकर्ता नाम और पासवर्ड जैसे लॉगिन क्रेडेंशियल्स शामिल हैं।
- **Current Session**/**Current Tabs**: वर्तमान ब्राउज़िंग सत्र और खुले टैब के बारे में डेटा।
- **Last Session**/**Last Tabs**: Chrome बंद होने से पहले अंतिम सत्र के दौरान सक्रिय साइटों के बारे में जानकारी।
- **Extensions**: ब्राउज़र एक्सटेंशन और ऐड-ऑन के लिए निर्देशिकाएँ।
- **Thumbnails**: वेबसाइट के थंबनेल संग्रहीत करता है।
- **Preferences**: एक फ़ाइल जिसमें जानकारी समृद्ध है, जिसमें प्लगइन्स, एक्सटेंशन्स, पॉप-अप, सूचनाएँ और अधिक के लिए सेटिंग्स शामिल हैं।
- **Browser’s built-in anti-phishing**: यह जांचने के लिए कि क्या एंटी-फिशिंग और मैलवेयर सुरक्षा सक्षम है, `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` चलाएँ। आउटपुट में `{"enabled: true,"}` देखें।

## **SQLite DB Data Recovery**

जैसा कि आप पिछले अनुभागों में देख सकते हैं, Chrome और Firefox दोनों **SQLite** डेटाबेस का उपयोग डेटा संग्रहीत करने के लिए करते हैं। **टूल का उपयोग करके हटाए गए प्रविष्टियों को पुनर्प्राप्त करना संभव है** [**sqlparse**](https://github.com/padfoot999/sqlparse) **या** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases)।

## **Internet Explorer 11**

Internet Explorer 11 अपने डेटा और मेटाडेटा को विभिन्न स्थानों में प्रबंधित करता है, संग्रहीत जानकारी और इसके संबंधित विवरणों को अलग करने में मदद करता है ताकि आसानी से पहुँच और प्रबंधन किया जा सके।

### Metadata Storage

Internet Explorer के लिए मेटाडेटा `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` में संग्रहीत होता है (जहाँ VX V01, V16, या V24 हो सकता है)। इसके साथ, `V01.log` फ़ाइल में `WebcacheVX.data` के साथ संशोधन समय में असंगति दिखाई दे सकती है, जो `esentutl /r V01 /d` का उपयोग करके मरम्मत की आवश्यकता को इंगित करती है। यह मेटाडेटा, जो एक ESE डेटाबेस में स्थित है, को photorec और [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) जैसे टूल का उपयोग करके पुनर्प्राप्त और निरीक्षण किया जा सकता है। **Containers** तालिका के भीतर, कोई यह पहचान सकता है कि प्रत्येक डेटा खंड कहाँ संग्रहीत है, जिसमें अन्य Microsoft टूल जैसे Skype के लिए कैश विवरण शामिल हैं।

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) टूल कैश निरीक्षण की अनुमति देता है, जिसमें कैश डेटा निकालने के लिए फ़ोल्डर स्थान की आवश्यकता होती है। कैश के लिए मेटाडेटा में फ़ाइल नाम, निर्देशिका, पहुँच संख्या, URL मूल, और कैश निर्माण, पहुँच, संशोधन, और समाप्ति समय को इंगित करने वाले टाइमस्टैम्प शामिल हैं।

### Cookies Management

कुकीज़ को [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) का उपयोग करके खोजा जा सकता है, जिसमें मेटाडेटा नाम, URLs, पहुँच संख्या, और विभिन्न समय-संबंधित विवरण शामिल हैं। स्थायी कुकीज़ `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` में संग्रहीत होती हैं, जबकि सत्र कुकीज़ मेमोरी में रहती हैं।

### Download Details

डाउनलोड मेटाडेटा [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) के माध्यम से सुलभ है, जिसमें विशिष्ट कंटेनर डेटा जैसे URL, फ़ाइल प्रकार, और डाउनलोड स्थान रखता है। भौतिक फ़ाइलें `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` के तहत पाई जा सकती हैं।

### Browsing History

ब्राउज़िंग इतिहास की समीक्षा करने के लिए, [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) का उपयोग किया जा सकता है, जिसमें निकाले गए इतिहास फ़ाइलों का स्थान और Internet Explorer के लिए कॉन्फ़िगरेशन की आवश्यकता होती है। यहाँ मेटाडेटा में संशोधन और पहुँच समय, साथ ही पहुँच संख्या शामिल है। इतिहास फ़ाइलें `%userprofile%\Appdata\Local\Microsoft\Windows\History` में स्थित हैं।

### Typed URLs

टाइप किए गए URLs और उनके उपयोग समय को रजिस्ट्री में `NTUSER.DAT` के तहत `Software\Microsoft\InternetExplorer\TypedURLs` और `Software\Microsoft\InternetExplorer\TypedURLsTime` में संग्रहीत किया गया है, जो उपयोगकर्ता द्वारा दर्ज किए गए अंतिम 50 URLs और उनके अंतिम इनपुट समय को ट्रैक करता है।

## Microsoft Edge

Microsoft Edge उपयोगकर्ता डेटा को `%userprofile%\Appdata\Local\Packages` में संग्रहीत करता है। विभिन्न डेटा प्रकारों के लिए पथ हैं:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari डेटा `/Users/$User/Library/Safari` में संग्रहीत होता है। प्रमुख फ़ाइलें शामिल हैं:

- **History.db**: `history_visits` और `history_items` तालिकाएँ URLs और यात्रा के टाइमस्टैम्प के साथ। क्वेरी करने के लिए `sqlite3` का उपयोग करें।
- **Downloads.plist**: डाउनलोड की गई फ़ाइलों के बारे में जानकारी।
- **Bookmarks.plist**: बुकमार्क किए गए URLs संग्रहीत करता है।
- **TopSites.plist**: सबसे अधिक देखी जाने वाली साइटें।
- **Extensions.plist**: Safari ब्राउज़र एक्सटेंशन्स की सूची। पुनर्प्राप्त करने के लिए `plutil` या `pluginkit` का उपयोग करें।
- **UserNotificationPermissions.plist**: डोमेन जो पुश सूचनाएँ भेजने की अनुमति देते हैं। पार्स करने के लिए `plutil` का उपयोग करें।
- **LastSession.plist**: अंतिम सत्र से टैब। पार्स करने के लिए `plutil` का उपयोग करें।
- **Browser’s built-in anti-phishing**: जांचें कि `defaults read com.apple.Safari WarnAboutFraudulentWebsites` का उपयोग करके। 1 का उत्तर संकेत करता है कि यह सुविधा सक्रिय है।

## Opera

Opera का डेटा `/Users/$USER/Library/Application Support/com.operasoftware.Opera` में स्थित है और इतिहास और डाउनलोड के लिए Chrome के प्रारूप को साझा करता है।

- **Browser’s built-in anti-phishing**: यह सत्यापित करें कि क्या Preferences फ़ाइल में `fraud_protection_enabled` को `true` पर सेट किया गया है, `grep` का उपयोग करके।

ये पथ और कमांड विभिन्न वेब ब्राउज़रों द्वारा संग्रहीत ब्राउज़िंग डेटा तक पहुँचने और समझने के लिए महत्वपूर्ण हैं।

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}

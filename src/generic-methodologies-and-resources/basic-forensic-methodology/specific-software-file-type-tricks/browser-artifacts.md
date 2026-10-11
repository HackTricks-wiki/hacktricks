# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts में वेब ब्राउज़र द्वारा संग्रहीत विभिन्न प्रकार का डेटा शामिल होता है, जैसे नेविगेशन हिस्ट्री, बुकमार्क और कैश डेटा। ये artifacts ऑपरेटिंग सिस्टम के विशिष्ट फ़ोल्डरों में रखे जाते हैं। इनकी लोकेशन और नाम अलग-अलग ब्राउज़र में भिन्न होते हैं, लेकिन आम तौर पर इनमें एक जैसे डेटा प्रकार संग्रहीत होते हैं।

सबसे आम browser artifacts का सारांश:

- **Navigation History**: उपयोगकर्ता द्वारा देखी गई वेबसाइटों का रिकॉर्ड रखती है, जो malicious साइटों पर विज़िट की पहचान करने में उपयोगी है।
- **Autocomplete Data**: बार-बार की गई खोजों पर आधारित सुझाव; नेविगेशन हिस्ट्री के साथ मिलाकर देखने पर उपयोगी जानकारी मिल सकती है।
- **Bookmarks**: उपयोगकर्ता द्वारा जल्दी पहुँचने के लिए सहेजी गई साइटें।
- **Extensions and Add-ons**: उपयोगकर्ता द्वारा इंस्टॉल किए गए ब्राउज़र extensions या add-ons।
- **Cache**: वेबसाइट लोड होने का समय कम करने के लिए वेब सामग्री (जैसे images, JavaScript files) संग्रहीत करता है और forensic analysis के लिए उपयोगी है।
- **Logins**: संग्रहीत login credentials।
- **Favicons**: वेबसाइटों से जुड़े icons, जो tabs और bookmarks में दिखाई देते हैं और उपयोगकर्ता के visits के बारे में अतिरिक्त जानकारी दे सकते हैं।
- **Browser Sessions**: खुले browser sessions से संबंधित डेटा।
- **Downloads**: ब्राउज़र के ज़रिए डाउनलोड की गई फ़ाइलों का रिकॉर्ड।
- **Form Data**: वेब फ़ॉर्म में दर्ज की गई जानकारी, जिसे भविष्य में autofill सुझावों के लिए सहेजा जाता है।
- **Thumbnails**: वेबसाइटों की preview images।
- **Custom Dictionary.txt**: उपयोगकर्ता द्वारा ब्राउज़र के dictionary में जोड़े गए शब्द।

## Firefox

Firefox उपयोगकर्ता का डेटा profiles में व्यवस्थित करता है, जो ऑपरेटिंग सिस्टम के अनुसार अलग-अलग स्थानों पर संग्रहीत होते हैं:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

इन डायरेक्टरी में मौजूद `profiles.ini` फ़ाइल उपयोगकर्ता profiles की सूची देती है। प्रत्येक profile का डेटा उस फ़ोल्डर में संग्रहीत होता है जिसका नाम `profiles.ini` में `Path` variable में दिया होता है। यह फ़ोल्डर `profiles.ini` वाली उसी डायरेक्टरी में होता है। यदि किसी profile का फ़ोल्डर मौजूद नहीं है, तो हो सकता है कि उसे हटा दिया गया हो।

प्रत्येक profile फ़ोल्डर में कई महत्वपूर्ण फ़ाइलें मिल सकती हैं:<sup>[[1]](#references)</sup>

- **places.sqlite**: हिस्ट्री, बुकमार्क और downloads संग्रहीत करता है। Windows पर [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) जैसे tools हिस्ट्री डेटा तक पहुँच सकते हैं।
  - हिस्ट्री और downloads की जानकारी निकालने के लिए खास SQL queries का उपयोग करें।
- **bookmarkbackups**: बुकमार्क के backups रखता है।
- **formhistory.sqlite**: वेब फ़ॉर्म का डेटा संग्रहीत करता है।
- **handlers.json**: protocol handlers का प्रबंधन करता है।
- **persdict.dat**: Custom dictionary के शब्द।
- **addons.json** और **extensions.sqlite**: इंस्टॉल किए गए add-ons और extensions की जानकारी।
- **cookies.sqlite**: Cookie storage; Windows पर इसकी जाँच के लिए [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) उपलब्ध है।
- **cache2/entries** या **startupCache**: Cache डेटा, जिसे [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) जैसे tools से देखा जा सकता है।
- **favicons.sqlite**: Favicons संग्रहीत करता है।
- **prefs.js**: उपयोगकर्ता की settings और preferences।
- **downloads.sqlite**: पुराने downloads का database, जो अब places.sqlite में एकीकृत है।
- **thumbnails**: वेबसाइट thumbnails।
- **logins.json**: Encrypted login जानकारी।
- **key4.db** या **key3.db**: संवेदनशील जानकारी को सुरक्षित रखने वाली encryption keys संग्रहीत करता है।

इसके अतिरिक्त, `prefs.js` में `browser.safebrowsing` entries खोजकर ब्राउज़र की anti-phishing settings की जाँच की जा सकती है। इससे पता चलता है कि safe browsing features सक्षम हैं या अक्षम।<sup>[[2]](#references)</sup>

किसी सुलभ profile से सहेजे गए logins को decrypt करने के लिए, यदि [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins) सेट किया गया है, तो उसे देना होगा या अलग से recover करना होगा; profile से वह password नहीं मिलता। पुष्टि करें कि recovered login से संबंधित web account में authenticate किया जा सकता है। Unix में root access के लिए अलग से यह साबित करना होगा कि credential Unix authentication में root के लिए भी स्वीकार किया जाता है। सहेजे गए logins देखने के लिए [firefox_decrypt](https://github.com/unode/firefox_decrypt) का उपयोग कर सकते हैं। नीचे दिए गए उदाहरण में password file से candidate Primary Passwords जाँचे जाते हैं:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![ब्राउज़र आर्टिफैक्ट्स - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome उपयोगकर्ता प्रोफ़ाइल को ऑपरेटिंग सिस्टम के अनुसार तय स्थानों पर स्टोर करता है:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

इन डायरेक्टरी के अंदर, ज़्यादातर उपयोगकर्ता डेटा **Default/** या **ChromeDefaultData/** फ़ोल्डर में मिलता है। नीचे दी गई फ़ाइलों में महत्वपूर्ण डेटा होता है:<sup>[[1]](#references)</sup>

- **History**: इसमें URLs, डाउनलोड और खोज के कीवर्ड होते हैं। Windows पर, इतिहास पढ़ने के लिए [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) का उपयोग किया जा सकता है। "Transition Type" कॉलम के कई अर्थ हैं, जिनमें लिंक पर उपयोगकर्ता के क्लिक, टाइप किए गए URLs, फ़ॉर्म सबमिशन और पेज रीफ़्रेश शामिल हैं।
- **Cookies**: इसमें cookies स्टोर होती हैं। जाँच के लिए [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) उपलब्ध है।
- **Cache**: इसमें कैश किया गया डेटा होता है। जाँच के लिए, Windows उपयोगकर्ता [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) का उपयोग कर सकते हैं।

  Electron पर आधारित डेस्कटॉप ऐप्स (जैसे, Discord) भी Chromium Simple Cache का उपयोग करते हैं और डिस्क पर विस्तृत आर्टिफैक्ट छोड़ते हैं। देखें:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: उपयोगकर्ता के बुकमार्क।
- **Web Data**: इसमें फ़ॉर्म का इतिहास होता है।
- **Favicons**: इसमें वेबसाइट के favicon स्टोर होते हैं।
- **Login Data**: इसमें उपयोगकर्ता नाम और पासवर्ड जैसे लॉगिन क्रेडेंशियल शामिल होते हैं।
- **Current Session**/**Current Tabs**: मौजूदा ब्राउज़िंग सेशन और खुले टैब का डेटा।
- **Last Session**/**Last Tabs**: Chrome बंद होने से पहले, पिछले सेशन में सक्रिय साइटों की जानकारी।
- **Extensions**: ब्राउज़र extensions और addons की डायरेक्टरी।
- **Thumbnails**: इसमें वेबसाइट के thumbnails स्टोर होते हैं।
- **Preferences**: प्लगइन, extensions, पॉप-अप, सूचनाओं और अन्य चीज़ों की सेटिंग सहित, जानकारी से भरपूर फ़ाइल।
- **Browser का अंतर्निहित anti-phishing**: anti-phishing और malware सुरक्षा सक्षम है या नहीं, यह जाँचने के लिए `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` चलाएँ। आउटपुट में `{"enabled: true,"}` ढूँढें।<sup>[[2]](#references)</sup>

Chromium प्रोफ़ाइल की `Local Extension Settings/<extension-id>/` डायरेक्टरी में extension का स्थानीय स्टेट हो सकता है, जिसमें पासवर्ड-मैनेजर की key material भी शामिल है। उदाहरण के लिए, [Passbolt के अनुसार उसकी एन्क्रिप्टेड private key ब्राउज़र extension के स्थानीय स्टोरेज में रखी जाती है](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), और उसका [Chrome extension ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) संबंधित डायरेक्टरी की पहचान करता है। केवल डायरेक्टरी का मौजूद होना यह साबित नहीं करता कि वहाँ key है, और न ही इससे vault अनलॉक होता है: उपयोगकर्ता के पास प्रोफ़ाइल डेटा, इस्तेमाल की जा सकने वाली private key और passphrase, तथा सर्वर के लिए अधिकृत recovery/authentication पथ होना चाहिए। यदि किसी vault item में ऑपरेटिंग-सिस्टम खाते का पासवर्ड है, तो खाते में उसके दोबारा उपयोग की अलग से पुष्टि करनी होगी। नियमित enumeration में केवल स्टोरेज पथ की रिपोर्ट दें; इसकी LevelDB फ़ाइलें या secret values न निकालें।

## **SQLite DB Data Recovery**

जैसा कि पिछले अनुभागों में देखा जा सकता है, Chrome और Firefox दोनों डेटा स्टोर करने के लिए **SQLite** डेटाबेस का उपयोग करते हैं। **टूल** [**sqlparse**](https://github.com/padfoot999/sqlparse) **या** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **की मदद से हटाई गई entries को रिकवर करना संभव है**।

## **Internet Explorer 11**

Internet Explorer 11 अपने डेटा और metadata को अलग-अलग स्थानों पर मैनेज करता है, जिससे स्टोर की गई जानकारी और उससे संबंधित विवरण अलग रहते हैं तथा उन्हें आसानी से एक्सेस और मैनेज किया जा सकता है।

### Metadata Storage

Internet Explorer का metadata `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` में स्टोर होता है (जहाँ VX का मान V01, V16 या V24 होता है)। इससे संबंधित `V01.log` फ़ाइल में, `WebcacheVX.data` के modification time से विसंगतियाँ दिख सकती हैं। यह `esentutl /r V01 /d` से repair करने की आवश्यकता दर्शा सकता है। ESE डेटाबेस में मौजूद इस metadata को photorec और [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) जैसे टूल से क्रमशः रिकवर और जाँचा जा सकता है। **Containers** टेबल में यह पता लगाया जा सकता है कि प्रत्येक डेटा सेगमेंट किस टेबल या कंटेनर में स्टोर है; इसमें Skype जैसे अन्य Microsoft टूल के cache का विवरण भी शामिल है।

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) टूल cache की जाँच करने देता है। इसके लिए cache डेटा निकालने वाले फ़ोल्डर का स्थान देना होता है। Cache के metadata में फ़ाइलनाम, डायरेक्टरी, access count, URL origin और cache बनने, एक्सेस होने, संशोधित होने तथा समाप्त होने के समय के timestamps शामिल होते हैं।

### Cookies Management

[IECookiesView](https://www.nirsoft.net/utils/iecookies.html) से cookies की जाँच की जा सकती है। इनके metadata में नाम, URLs, access counts और समय से जुड़ी विभिन्न जानकारी शामिल होती है। Persistent cookies `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` में स्टोर होती हैं, जबकि session cookies मेमोरी में रहती हैं।

### Download Details

डाउनलोड का metadata [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) से एक्सेस किया जा सकता है। कुछ विशिष्ट कंटेनरों में URL, फ़ाइल प्रकार और डाउनलोड स्थान जैसी जानकारी होती है। फ़िज़िकल फ़ाइलें `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` में मिल सकती हैं।

### Browsing History

ब्राउज़िंग इतिहास देखने के लिए [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) का उपयोग किया जा सकता है। इसके लिए निकाली गई history फ़ाइलों का स्थान और Internet Explorer का कॉन्फ़िगरेशन देना आवश्यक है। इस metadata में modification और access times के साथ access counts भी शामिल होते हैं। History फ़ाइलें `%userprofile%\Appdata\Local\Microsoft\Windows\History` में होती हैं।

### Typed URLs

टाइप किए गए URLs और उनके उपयोग का समय, `NTUSER.DAT` रजिस्ट्री में `Software\Microsoft\InternetExplorer\TypedURLs` और `Software\Microsoft\InternetExplorer\TypedURLsTime` के अंतर्गत स्टोर होता है। इसमें उपयोगकर्ता द्वारा दर्ज किए गए पिछले 50 URLs और उन्हें आखिरी बार दर्ज करने का समय ट्रैक किया जाता है।

## Microsoft Edge

Microsoft Edge उपयोगकर्ता डेटा `%userprofile%\Appdata\Local\Packages` में स्टोर करता है। विभिन्न प्रकार के डेटा के पथ ये हैं:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari डेटा `/Users/$User/Library/Safari` में स्टोर होता है। मुख्य फ़ाइलें:<sup>[[3]](#references)</sup>

- **History.db**: इसमें URLs और visit timestamps वाली `history_visits` और `history_items` टेबल होती हैं। क्वेरी करने के लिए `sqlite3` का उपयोग करें।
- **Downloads.plist**: डाउनलोड की गई फ़ाइलों की जानकारी।
- **Bookmarks.plist**: बुकमार्क किए गए URLs स्टोर करती है।
- **TopSites.plist**: सबसे ज़्यादा देखी गई साइटें।
- **Extensions.plist**: Safari ब्राउज़र extensions की सूची। जानकारी पाने के लिए `plutil` या `pluginkit` का उपयोग करें।
- **UserNotificationPermissions.plist**: वे domains जिन्हें push notifications भेजने की अनुमति है। इसे parse करने के लिए `plutil` का उपयोग करें।
- **LastSession.plist**: पिछले सेशन के टैब। इसे parse करने के लिए `plutil` का उपयोग करें।
- **ब्राउज़र का अंतर्निहित anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` चलाकर जाँचें। 1 का उत्तर बताता है कि यह सुविधा सक्रिय है।<sup>[[2]](#references)</sup>

## Opera

Opera का डेटा `/Users/$USER/Library/Application Support/com.operasoftware.Opera` में मौजूद होता है। History और डाउनलोड के लिए यह Chrome वाला फ़ॉर्मैट इस्तेमाल करता है।

- **ब्राउज़र का अंतर्निहित anti-phishing**: `grep` का उपयोग करके जाँचें कि Preferences फ़ाइल में `fraud_protection_enabled` का मान `true` है या नहीं।<sup>[[2]](#references)</sup>

ये पथ और कमांड विभिन्न वेब ब्राउज़र द्वारा स्टोर किए गए ब्राउज़िंग डेटा को एक्सेस और समझने के लिए महत्वपूर्ण हैं।

## References

- [1] [वेब ब्राउज़र फॉरेंसिक्स: वेब ब्राउज़र का फॉरेंसिक विश्लेषण करने की मार्गदर्शिका](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | भाग 3: सिस्टम में हेरफेर](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Jaron Bradley द्वारा स्क्रिप्टिंग और विश्लेषण](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}

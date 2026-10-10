# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts में वेब ब्राउज़र द्वारा संग्रहीत विभिन्न प्रकार के डेटा शामिल होते हैं, जैसे नेविगेशन हिस्ट्री, बुकमार्क और cache डेटा। ये artifacts ऑपरेटिंग सिस्टम के भीतर विशिष्ट फ़ोल्डरों में रखे जाते हैं। इनका स्थान और नाम ब्राउज़र के अनुसार अलग-अलग होता है, लेकिन आम तौर पर इनमें समान प्रकार का डेटा संग्रहीत होता है।

यहाँ सबसे आम browser artifacts का सारांश दिया गया है:

- **Navigation History**: उपयोगकर्ता द्वारा देखी गई वेबसाइटों का रिकॉर्ड रखती है, जो दुर्भावनापूर्ण साइटों पर विज़िट की पहचान करने में उपयोगी है।
- **Autocomplete Data**: अक्सर की गई खोजों पर आधारित सुझाव, जो navigation history के साथ मिलाने पर उपयोगी जानकारी देते हैं।
- **Bookmarks**: उपयोगकर्ता द्वारा जल्दी पहुँचने के लिए सहेजी गई साइटें।
- **Extensions and Add-ons**: उपयोगकर्ता द्वारा इंस्टॉल किए गए browser extensions या add-ons।
- **Cache**: वेबसाइट लोड होने का समय कम करने के लिए वेब सामग्री (जैसे, images और JavaScript files) संग्रहीत करता है और forensic analysis के लिए उपयोगी है।
- **Logins**: संग्रहीत login credentials।
- **Favicons**: वेबसाइटों से जुड़े icons, जो tabs और bookmarks में दिखाई देते हैं और उपयोगकर्ता की विज़िट के बारे में अतिरिक्त जानकारी देने में उपयोगी हैं।
- **Browser Sessions**: खुले browser sessions से संबंधित डेटा।
- **Downloads**: ब्राउज़र के ज़रिए डाउनलोड की गई फ़ाइलों का रिकॉर्ड।
- **Form Data**: वेब फ़ॉर्म में दर्ज की गई जानकारी, जिसे भविष्य में autofill सुझावों के लिए सहेजा जाता है।
- **Thumbnails**: वेबसाइटों की preview images।
- **Custom Dictionary.txt**: उपयोगकर्ता द्वारा ब्राउज़र के dictionary में जोड़े गए शब्द।

## Firefox

Firefox उपयोगकर्ता का डेटा profiles के भीतर व्यवस्थित करता है, जिन्हें ऑपरेटिंग सिस्टम के आधार पर अलग-अलग स्थानों पर संग्रहीत किया जाता है:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

इन directories में मौजूद `profiles.ini` फ़ाइल उपयोगकर्ता के profiles की सूची देती है। प्रत्येक profile का डेटा, `profiles.ini` के उसी directory में मौजूद `profiles.ini` के `Path` variable में दिए गए नाम वाले फ़ोल्डर में संग्रहीत होता है। यदि किसी profile का फ़ोल्डर मौजूद नहीं है, तो हो सकता है कि उसे हटा दिया गया हो।

हर profile फ़ोल्डर में कई महत्वपूर्ण फ़ाइलें मिल सकती हैं:<sup>[[1]](#references)</sup>

- **places.sqlite**: History, bookmarks और downloads संग्रहीत करता है। Windows पर [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) जैसे tools से history डेटा देखा जा सकता है।
  - History और downloads की जानकारी निकालने के लिए विशिष्ट SQL queries का उपयोग करें।
- **bookmarkbackups**: Bookmarks के backups रखता है।
- **formhistory.sqlite**: वेब फ़ॉर्म का डेटा संग्रहीत करता है।
- **handlers.json**: Protocol handlers प्रबंधित करता है।
- **persdict.dat**: Custom dictionary के शब्द।
- **addons.json** और **extensions.sqlite**: इंस्टॉल किए गए add-ons और extensions की जानकारी।
- **cookies.sqlite**: Cookies संग्रहीत करता है; Windows पर इसकी जाँच के लिए [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) उपलब्ध है।
- **cache2/entries** या **startupCache**: Cache डेटा, जिसे [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) जैसे tools से देखा जा सकता है।
- **favicons.sqlite**: Favicons संग्रहीत करता है।
- **prefs.js**: उपयोगकर्ता की settings और preferences।
- **downloads.sqlite**: पुराने downloads database को अब places.sqlite में शामिल कर दिया गया है।
- **thumbnails**: वेबसाइटों के thumbnails।
- **logins.json**: एन्क्रिप्ट की गई login जानकारी।
- **key4.db** या **key3.db**: संवेदनशील जानकारी सुरक्षित रखने के लिए encryption keys संग्रहीत करता है।

इसके अलावा, ब्राउज़र की anti-phishing settings देखने के लिए `prefs.js` में `browser.safebrowsing` entries खोजें। इनसे पता चलता है कि safe browsing सुविधाएँ सक्षम हैं या अक्षम।<sup>[[2]](#references)</sup>

किसी उपलब्ध profile से सहेजे गए logins को decrypt करने के लिए, यदि [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins) कॉन्फ़िगर किया गया है, तो उसे देना होगा या अलग से recover करना होगा; profile से वह password पता नहीं चलता। पुष्टि करें कि recover किया गया कोई भी login उसके वेब खाते में authenticate होता है। Unix root access के लिए अलग से यह साबित करना आवश्यक है कि credential Unix authentication में root के लिए भी स्वीकार किया जाता है। सहेजे गए logins की समीक्षा [firefox_decrypt](https://github.com/unode/firefox_decrypt) से की जा सकती है। निम्नलिखित उदाहरण password file से संभावित Primary Passwords को जाँचता है:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![ब्राउज़र artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome, operating system के आधार पर विशिष्ट स्थानों पर user profiles संग्रहीत करता है:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

इन directories में, अधिकांश user data **Default/** या **ChromeDefaultData/** folders में मिल सकता है। इन files में महत्वपूर्ण data होता है:<sup>[[1]](#references)</sup>

- **History**: इसमें URLs, downloads और search keywords होते हैं। Windows पर, history पढ़ने के लिए [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) का उपयोग किया जा सकता है। "Transition Type" column के कई अर्थ हैं, जिनमें links पर user के clicks, typed URLs, form submissions और page reloads शामिल हैं।
- **Cookies**: इसमें cookies संग्रहीत होती हैं। निरीक्षण के लिए [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) उपलब्ध है।
- **Cache**: इसमें cached data होता है। निरीक्षण के लिए Windows users [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) का उपयोग कर सकते हैं।

  Electron-आधारित desktop apps (जैसे, Discord) भी Chromium Simple Cache का उपयोग करते हैं और disk पर विस्तृत artifacts छोड़ते हैं। देखें:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: User के bookmarks।
- **Web Data**: इसमें form history होती है।
- **Favicons**: इसमें website favicons संग्रहीत होते हैं।
- **Login Data**: इसमें usernames और passwords जैसे login credentials होते हैं।
- **Current Session**/**Current Tabs**: मौजूदा browsing session और खुले tabs का data।
- **Last Session**/**Last Tabs**: Chrome बंद होने से पहले पिछले session में सक्रिय sites की जानकारी।
- **Extensions**: Browser extensions और addons की directories।
- **Thumbnails**: इसमें website thumbnails संग्रहीत होते हैं।
- **Preferences**: plugins, extensions, pop-ups, notifications आदि की settings समेत, जानकारी से भरपूर एक file।
- **ब्राउज़र का अंतर्निहित anti-phishing**: anti-phishing और malware protection सक्षम हैं या नहीं, यह जाँचने के लिए `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` चलाएँ। Output में `{"enabled: true,"}` देखें।<sup>[[2]](#references)</sup>

Chromium profile की `Local Extension Settings/<extension-id>/` directory में extension-local state हो सकती है, जिसमें password-manager key material भी शामिल है। उदाहरण के लिए, [Passbolt के अनुसार उसकी encrypted private key browser extension के local storage में रखी जाती है](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/), और उसकी [Chrome extension ID](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) संबंधित directory की पहचान करती है। केवल directory मौजूद होने से यह साबित नहीं होता कि उसमें key है या vault unlock हो सकता है: user के पास profile data, उपयोग योग्य private key और passphrase, तथा server तक पहुँचने का अधिकृत recovery/authentication path होना चाहिए। किसी vault item में मौजूद operating-system account password के लिए account reuse की अलग से पुष्टि आवश्यक है। नियमित enumeration में केवल storage path की जानकारी दें; इसकी LevelDB files या secret values न निकालें।

## **SQLite DB Data Recovery**

जैसा कि पिछले sections में देखा जा सकता है, Chrome और Firefox दोनों data संग्रहीत करने के लिए **SQLite** databases का उपयोग करते हैं। [**sqlparse**](https://github.com/padfoot999/sqlparse) **या** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **tool का उपयोग करके deleted entries recover करना संभव है।**

## **Internet Explorer 11**

Internet Explorer 11 अपना data और metadata कई स्थानों पर रखता है, जिससे संग्रहीत जानकारी और उससे संबंधित विवरण अलग-अलग रहते हैं तथा उन्हें आसानी से देखा और प्रबंधित किया जा सकता है।

### Metadata Storage

Internet Explorer का metadata `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` में संग्रहीत होता है (जहाँ VX, V01, V16 या V24 हो सकता है)। इसके साथ मौजूद `V01.log` file का modification time, `WebcacheVX.data` से अलग हो सकता है। यह `esentutl /r V01 /d` से repair की आवश्यकता का संकेत हो सकता है। ESE database में रखा यह metadata photorec और [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) जैसे tools से क्रमशः recover और inspect किया जा सकता है। **Containers** table में देखा जा सकता है कि प्रत्येक data segment किन tables या containers में संग्रहीत है; इसमें Skype जैसे अन्य Microsoft tools के cache का विवरण भी शामिल है।

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) tool cache inspect करने देता है। इसके लिए cache data extraction folder का स्थान देना आवश्यक है। Cache metadata में filename, directory, access count, URL origin, और cache बनने, access होने, modify होने तथा expire होने के timestamps शामिल हैं।

### Cookies Management

[IECookiesView](https://www.nirsoft.net/utils/iecookies.html) से cookies देखी जा सकती हैं। इनके metadata में names, URLs, access counts और समय से जुड़ी अलग-अलग जानकारी शामिल होती है। Persistent cookies `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` में संग्रहीत होती हैं, जबकि session cookies memory में रहती हैं।

### Download Details

Downloads का metadata [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) से देखा जा सकता है। विशिष्ट containers में URL, file type और download location जैसी जानकारी होती है। वास्तविक files `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` में मिल सकती हैं।

### Browsing History

Browsing history देखने के लिए [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) का उपयोग किया जा सकता है। इसके लिए extracted history files का स्थान देना और Internet Explorer को configure करना आवश्यक है। इस metadata में modification और access times के साथ access counts भी शामिल होते हैं। History files `%userprofile%\Appdata\Local\Microsoft\Windows\History` में होती हैं।

### Typed URLs

Typed URLs और उनके उपयोग का समय, registry में `NTUSER.DAT` के अंतर्गत `Software\Microsoft\InternetExplorer\TypedURLs` और `Software\Microsoft\InternetExplorer\TypedURLsTime` में संग्रहीत होते हैं। इनमें user द्वारा दर्ज किए गए पिछले 50 URLs और उनके दर्ज किए जाने का अंतिम समय track होता है।

## Microsoft Edge

Microsoft Edge user data `%userprofile%\Appdata\Local\Packages` में संग्रहीत करता है। विभिन्न प्रकार के data के paths ये हैं:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari data `/Users/$User/Library/Safari` में संग्रहीत होता है। मुख्य files में शामिल हैं:<sup>[[3]](#references)</sup>

- **History.db**: इसमें URLs और visit timestamps वाले `history_visits` और `history_items` tables होते हैं। Query करने के लिए `sqlite3` का उपयोग करें।
- **Downloads.plist**: Download की गई files की जानकारी।
- **Bookmarks.plist**: Bookmarked URLs संग्रहीत करता है।
- **TopSites.plist**: सबसे अधिक देखी गई sites।
- **Extensions.plist**: Safari browser extensions की सूची। इन्हें पाने के लिए `plutil` या `pluginkit` का उपयोग करें।
- **UserNotificationPermissions.plist**: Push notifications की अनुमति वाले domains। Parse करने के लिए `plutil` का उपयोग करें।
- **LastSession.plist**: पिछले session के tabs। Parse करने के लिए `plutil` का उपयोग करें।
- **ब्राउज़र का अंतर्निहित anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` से जाँचें। Response `1` होने का अर्थ है कि यह सुविधा सक्रिय है।<sup>[[2]](#references)</sup>

## Opera

Opera का data `/Users/$USER/Library/Application Support/com.operasoftware.Opera` में रहता है और history तथा downloads के लिए Chrome वाला format उपयोग करता है।

- **ब्राउज़र का अंतर्निहित anti-phishing**: `grep` का उपयोग करके Preferences file में जाँचें कि `fraud_protection_enabled` का मान `true` है या नहीं।<sup>[[2]](#references)</sup>

अलग-अलग web browsers में संग्रहीत browsing data तक पहुँचने और उसे समझने के लिए ये paths और commands महत्वपूर्ण हैं।

## References

- [1] [Web Browsers Forensics: Web Browsers के forensic analysis की मार्गदर्शिका](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | भाग 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Jaron Bradley द्वारा Scripting और Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}

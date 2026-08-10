# Browser Artifacts

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts में web browsers द्वारा संग्रहीत विभिन्न प्रकार का data शामिल होता है, जैसे navigation history, bookmarks और cache data। ये artifacts operating system के भीतर विशिष्ट folders में रखे जाते हैं। इनका location और नाम अलग-अलग browsers में भिन्न हो सकता है, लेकिन आमतौर पर इनमें समान प्रकार का data संग्रहीत होता है।

यहाँ सबसे सामान्य browser artifacts का सारांश दिया गया है:

- **Navigation History**: User द्वारा देखी गई websites को track करता है, जो malicious sites पर visits की पहचान करने में उपयोगी है।
- **Autocomplete Data**: अक्सर की जाने वाली searches पर आधारित suggestions, navigation history के साथ मिलाने पर उपयोगी insights प्रदान करते हैं।
- **Bookmarks**: User द्वारा quick access के लिए save की गई sites।
- **Extensions and Add-ons**: User द्वारा install किए गए browser extensions या add-ons।
- **Cache**: Website loading times को बेहतर बनाने के लिए web content (जैसे images और JavaScript files) संग्रहीत करता है, जो forensic analysis के लिए उपयोगी होता है।
- **Logins**: संग्रहीत login credentials।
- **Favicons**: Websites से जुड़े icons, जो tabs और bookmarks में दिखाई देते हैं और user visits के बारे में अतिरिक्त जानकारी के लिए उपयोगी होते हैं।
- **Browser Sessions**: Open browser sessions से संबंधित data।
- **Downloads**: Browser के माध्यम से download की गई files के records।
- **Form Data**: Web forms में दर्ज की गई information, जिसे भविष्य के autofill suggestions के लिए save किया जाता है।
- **Thumbnails**: Websites की preview images।
- **Custom Dictionary.txt**: User द्वारा browser के dictionary में जोड़े गए words।

## Firefox

Firefox user data को profiles के भीतर व्यवस्थित करता है, जो operating system के आधार पर विशिष्ट locations में संग्रहीत होते हैं:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

इन directories के भीतर मौजूद `profiles.ini` file user profiles की सूची देती है। प्रत्येक profile का data `profiles.ini` में `Path` variable के भीतर दिए गए नाम वाले folder में संग्रहीत होता है, जो उसी directory में स्थित होता है जिसमें स्वयं `profiles.ini` मौजूद है। यदि किसी profile का folder मौजूद नहीं है, तो संभव है कि उसे delete कर दिया गया हो।

प्रत्येक profile folder के भीतर आपको कई महत्वपूर्ण files मिल सकती हैं:<sup>[[1]](#references)</sup>

- **places.sqlite**: History, bookmarks और downloads संग्रहीत करता है। Windows पर [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) जैसे tools history data तक access कर सकते हैं।
- History और downloads information extract करने के लिए specific SQL queries का उपयोग करें।
- **bookmarkbackups**: Bookmarks के backups रखता है।
- **formhistory.sqlite**: Web form data संग्रहीत करता है।
- **handlers.json**: Protocol handlers को manage करता है।
- **persdict.dat**: Custom dictionary words।
- **addons.json** और **extensions.sqlite**: Installed add-ons और extensions की information।
- **cookies.sqlite**: Cookie storage, जिसे Windows पर inspection के लिए [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) के माध्यम से देखा जा सकता है।
- **cache2/entries** या **startupCache**: Cache data, जिसे [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) जैसे tools के माध्यम से access किया जा सकता है।
- **favicons.sqlite**: Favicons संग्रहीत करता है।
- **prefs.js**: User settings और preferences।
- **downloads.sqlite**: पुराना downloads database, जिसे अब places.sqlite में integrate कर दिया गया है।
- **thumbnails**: Website thumbnails।
- **logins.json**: Encrypted login information।
- **key4.db** या **key3.db**: Sensitive information को secure करने के लिए encryption keys संग्रहीत करता है।

इसके अतिरिक्त, browser की anti-phishing settings की जाँच `prefs.js` में `browser.safebrowsing` entries खोजकर की जा सकती है। ये entries बताती हैं कि safe browsing features enabled हैं या disabled।<sup>[[2]](#references)</sup>

Master password को decrypt करने का प्रयास करने के लिए आप [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) का उपयोग कर सकते हैं\
निम्न script और call के साथ आप brute force के लिए password file specify कर सकते हैं:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Browsers Artifacts - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome operating system के आधार पर user profiles को विशिष्ट locations में store करता है:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

इन directories के भीतर, अधिकांश user data **Default/** या **ChromeDefaultData/** folders में पाया जा सकता है। निम्न files में महत्वपूर्ण data होता है:<sup>[[1]](#references)</sup>

- **History**: URLs, downloads और search keywords रखता है। Windows पर history पढ़ने के लिए [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) का उपयोग किया जा सकता है। "Transition Type" column के विभिन्न अर्थ होते हैं, जिनमें links पर user clicks, typed URLs, form submissions और page reloads शामिल हैं।
- **Cookies**: Cookies store करता है। Inspection के लिए [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) उपलब्ध है।
- **Cache**: Cached data रखता है। Inspection के लिए Windows users [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) का उपयोग कर सकते हैं।

Electron-based desktop apps (जैसे Discord) भी Chromium Simple Cache का उपयोग करते हैं और disk पर विस्तृत artifacts छोड़ते हैं। देखें:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: User bookmarks।
- **Web Data**: Form history रखता है।
- **Favicons**: Website favicons store करता है।
- **Login Data**: Usernames और passwords जैसे login credentials शामिल करता है।
- **Current Session**/**Current Tabs**: Current browsing session और open tabs से संबंधित data।
- **Last Session**/**Last Tabs**: Chrome बंद होने से पहले last session के दौरान active sites की information।
- **Extensions**: Browser extensions और addons के लिए directories।
- **Thumbnails**: Website thumbnails store करता है।
- **Preferences**: Plugins, extensions, pop-ups, notifications और अन्य settings सहित विस्तृत information वाली file।
- **Browser’s built-in anti-phishing**: यह जांचने के लिए कि anti-phishing और malware protection enabled हैं या नहीं, `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` चलाएं। Output में `{"enabled: true,"}` खोजें।<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

जैसा कि पिछले sections में देखा जा सकता है, Chrome और Firefox दोनों data store करने के लिए **SQLite** databases का उपयोग करते हैं। [**sqlparse**](https://github.com/padfoot999/sqlparse) **या** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **tool का उपयोग करके deleted entries को recover करना संभव है**।

## **Internet Explorer 11**

Internet Explorer 11 अपने data और metadata को विभिन्न locations में manage करता है, जिससे stored information और उससे संबंधित details को अलग करना तथा आसानी से access और manage करना संभव होता है।

### Metadata Storage

Internet Explorer का metadata `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` में store होता है (जहां VX, V01, V16 या V24 होता है)। इसके साथ, `V01.log` file में `WebcacheVX.data` के साथ modification time discrepancies दिखाई दे सकती हैं, जो `esentutl /r V01 /d` का उपयोग करके repair की आवश्यकता दर्शाती हैं। ESE database में मौजूद इस metadata को photorec और [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) जैसे tools का उपयोग करके क्रमशः recover और inspect किया जा सकता है। **Containers** table के भीतर, यह पता लगाया जा सकता है कि प्रत्येक data segment किन specific tables या containers में store है, जिसमें Skype जैसे अन्य Microsoft tools के cache details भी शामिल हैं।

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) tool cache inspection की सुविधा देता है और इसके लिए cache data extraction folder location आवश्यक होती है। Cache के metadata में filename, directory, access count, URL origin और cache creation, access, modification तथा expiry times दर्शाने वाले timestamps शामिल होते हैं।

### Cookies Management

Cookies को [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) का उपयोग करके explore किया जा सकता है। इसके metadata में names, URLs, access counts और विभिन्न time-related details शामिल होते हैं। Persistent cookies `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` में store होते हैं, जबकि session cookies memory में रहते हैं।

### Download Details

Downloads का metadata [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) के माध्यम से access किया जा सकता है। Specific containers में URL, file type और download location जैसे data होते हैं। Physical files `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` में मिल सकती हैं।

### Browsing History

Browsing history की समीक्षा के लिए [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) का उपयोग किया जा सकता है। इसके लिए extracted history files की location और Internet Explorer का configuration आवश्यक है। यहां metadata में modification और access times के साथ access counts भी शामिल होते हैं। History files `%userprofile%\Appdata\Local\Microsoft\Windows\History` में located होती हैं।

### Typed URLs

Typed URLs और उनके usage timings registry में `NTUSER.DAT` के अंतर्गत `Software\Microsoft\InternetExplorer\TypedURLs` और `Software\Microsoft\InternetExplorer\TypedURLsTime` में store होते हैं। ये user द्वारा दर्ज किए गए last 50 URLs और उनके last input times को track करते हैं।

## Microsoft Edge

Microsoft Edge user data को `%userprofile%\Appdata\Local\Packages` में store करता है। विभिन्न data types के paths हैं:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari data `/Users/$User/Library/Safari` पर store होता है। मुख्य files में शामिल हैं:<sup>[[3]](#references)</sup>

- **History.db**: `history_visits` और `history_items` tables में URLs और visit timestamps होते हैं। Query करने के लिए `sqlite3` का उपयोग करें।
- **Downloads.plist**: Download की गई files की information।
- **Bookmarks.plist**: Bookmarked URLs store करता है।
- **TopSites.plist**: सबसे अधिक visit की गई sites।
- **Extensions.plist**: Safari browser extensions की list। Retrieve करने के लिए `plutil` या `pluginkit` का उपयोग करें।
- **UserNotificationPermissions.plist**: Push notifications की अनुमति वाले domains। Parse करने के लिए `plutil` का उपयोग करें।
- **LastSession.plist**: Last session के tabs। Parse करने के लिए `plutil` का उपयोग करें।
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` का उपयोग करके जांचें। 1 का response दर्शाता है कि feature active है।<sup>[[2]](#references)</sup>

## Opera

Opera का data `/Users/$USER/Library/Application Support/com.operasoftware.Opera` में रहता है और history तथा downloads के लिए Chrome का format share करता है।

- **Browser’s built-in anti-phishing**: `grep` का उपयोग करके Preferences file में `fraud_protection_enabled` के `true` पर set होने की जांच करें।<sup>[[2]](#references)</sup>

विभिन्न web browsers द्वारा store किए गए browsing data को access और समझने के लिए ये paths और commands महत्वपूर्ण हैं।

## References

- [1] [Web Browsers Forensics: Web Browsers Forensic Analysis करने की Guide](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Jaron Bradley द्वारा Scripting and Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}

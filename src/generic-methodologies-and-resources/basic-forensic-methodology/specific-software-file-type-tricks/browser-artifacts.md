# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts, web browsers tarafından navigation history, bookmarks ve cache data gibi çeşitli data türlerinin depolanmasıyla oluşur. Bu artifacts, işletim sistemi içinde belirli klasörlerde tutulur; konumları ve adları browser'lara göre değişse de genellikle benzer data türlerini depolarlar.

En yaygın browser artifacts için özet:

- **Navigation History**: Kullanıcının web sitelerine ziyaretlerini takip eder ve malicious sitelere yapılan ziyaretleri belirlemek için kullanışlıdır.
- **Autocomplete Data**: Sık yapılan aramalara dayalı öneriler sunar ve navigation history ile birlikte kullanıldığında içgörü sağlar.
- **Bookmarks**: Kullanıcı tarafından hızlı erişim için kaydedilen siteler.
- **Extensions and Add-ons**: Kullanıcı tarafından yüklenen browser extensions veya add-ons.
- **Cache**: Website loading times değerlerini iyileştirmek için web content'i (ör. images, JavaScript files) depolar ve forensic analysis için değerlidir.
- **Logins**: Depolanan login credentials.
- **Favicons**: Web siteleriyle ilişkilendirilen, tabs ve bookmarks içinde görünen ve kullanıcı ziyaretleri hakkında ek bilgi sağlayan icons.
- **Browser Sessions**: Açık browser sessions ile ilgili data.
- **Downloads**: Browser üzerinden indirilen files kayıtları.
- **Form Data**: Web forms içine girilen ve gelecekteki autofill suggestions için kaydedilen bilgiler.
- **Thumbnails**: Web sitelerinin preview images.
- **Custom Dictionary.txt**: Kullanıcı tarafından browser'ın dictionary'sine eklenen words.

## Firefox

Firefox, kullanıcı data'sını işletim sistemine göre belirli konumlarda depolanan profiles içinde düzenler:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu directories içinde bulunan bir `profiles.ini` file'ı kullanıcı profiles'ını listeler. Her profile'ın data'sı, `profiles.ini` içindeki `Path` variable'ında belirtilen ve `profiles.ini` dosyasının kendisiyle aynı directory içinde bulunan bir folder'da depolanır. Bir profile'ın folder'ı eksikse silinmiş olabilir.

Her profile folder'ı içinde birkaç önemli file bulabilirsiniz:<sup>[[1]](#references)</sup>

- **places.sqlite**: History, bookmarks ve downloads depolar. Windows'ta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi tools history data'sına erişebilir.
- History ve downloads bilgilerini çıkarmak için specific SQL queries kullanın.
- **bookmarkbackups**: Bookmarks backups içerir.
- **formhistory.sqlite**: Web form data'sını depolar.
- **handlers.json**: Protocol handlers'ı yönetir.
- **persdict.dat**: Custom dictionary words.
- **addons.json** ve **extensions.sqlite**: Yüklü add-ons ve extensions hakkında bilgiler.
- **cookies.sqlite**: Cookie storage; Windows'ta inceleme için [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) kullanılabilir.
- **cache2/entries** veya **startupCache**: [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi tools aracılığıyla erişilebilen cache data.
- **favicons.sqlite**: Favicons depolar.
- **prefs.js**: Kullanıcı settings ve preferences.
- **downloads.sqlite**: Artık places.sqlite içine entegre edilmiş eski downloads database'i.
- **thumbnails**: Website thumbnails.
- **logins.json**: Encrypted login information.
- **key4.db** veya **key3.db**: Sensitive information'ı korumak için kullanılan encryption keys'i depolar.

Ek olarak, browser'ın anti-phishing settings kontrolü, `prefs.js` içinde `browser.safebrowsing` entries aranarak yapılabilir; bu entries safe browsing features'ın enabled veya disabled olup olmadığını gösterir.<sup>[[2]](#references)</sup>

Master password'ü decrypt etmeyi denemek için [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) kullanabilirsiniz\
Aşağıdaki script ve call ile brute force yapmak için bir password file belirtebilirsiniz:
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

Google Chrome, işletim sistemine bağlı olarak kullanıcı profillerini belirli konumlarda saklar:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinlerde, kullanıcı verilerinin çoğu **Default/** veya **ChromeDefaultData/** klasörlerinde bulunabilir. Aşağıdaki dosyalar önemli veriler içerir:<sup>[[1]](#references)</sup>

- **History**: URL'leri, downloads ve arama anahtar kelimelerini içerir. Windows'ta geçmişi okumak için [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılabilir. "Transition Type" sütununun çeşitli anlamları vardır; bunlar arasında kullanıcıların bağlantılara tıklaması, yazılan URL'ler, form gönderimleri ve sayfa yeniden yüklemeleri bulunur.
- **Cookies**: Cookie'leri saklar. İnceleme için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) kullanılabilir.
- **Cache**: Önbelleğe alınmış verileri içerir. İncelemek için Windows kullanıcıları [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) aracını kullanabilir.

Electron tabanlı desktop uygulamaları (ör. Discord) ayrıca Chromium Simple Cache kullanır ve disk üzerinde zengin artifact'ler bırakır. Bkz.:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Kullanıcı bookmarks'ları.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi favicon'larını saklar.
- **Login Data**: Kullanıcı adları ve password'ler gibi login credential'larını içerir.
- **Current Session**/**Current Tabs**: Mevcut browsing session ve açık tab'ler hakkındaki veriler.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önceki son session sırasında aktif olan siteler hakkındaki bilgiler.
- **Extensions**: Browser extension'ları ve addon'ları için dizinler.
- **Thumbnails**: Web sitesi thumbnail'larını saklar.
- **Preferences**: Plugin'ler, extension'lar, pop-up'lar, notification'lar ve daha fazlasına ilişkin ayarlar dahil olmak üzere zengin bilgiler içeren bir dosya.
- **Browser’s built-in anti-phishing**: Anti-phishing ve malware protection'ın etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` komutunu çalıştırın. Çıktıda `{"enabled: true,"}` ifadesini arayın.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Önceki bölümlerde gözlemleyebileceğiniz gibi Chrome ve Firefox, verileri saklamak için **SQLite** database'lerini kullanır. Silinen entry'leri [**sqlparse**](https://github.com/padfoot999/sqlparse) **veya** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **aracını kullanarak kurtarmak** mümkündür.

## **Internet Explorer 11**

Internet Explorer 11, verilerini ve metadata'sını çeşitli konumlarda yönetir. Bu, saklanan bilgilerin ve ilgili ayrıntılarının kolay erişim ve yönetim için ayrılmasına yardımcı olur.

### Metadata Storage

Internet Explorer metadata'sı `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` konumunda saklanır (VX, V01, V16 veya V24 olabilir). Buna eşlik eden `V01.log` dosyası, `WebcacheVX.data` ile modification time arasında farklılıklar gösterebilir ve bu da `esentutl /r V01 /d` kullanılarak repair yapılması gerektiğine işaret eder. Bir ESE database'inde bulunan bu metadata, sırasıyla photorec ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi araçlar kullanılarak kurtarılabilir ve incelenebilir. **Containers** tablosunda, Skype gibi diğer Microsoft araçlarına ait cache ayrıntıları da dahil olmak üzere her data segmentinin saklandığı belirli table'lar veya container'lar belirlenebilir.

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı cache incelemesine olanak tanır ve cache data extraction folder konumunun belirtilmesini gerektirir. Cache metadata'sı filename, directory, access count, URL origin ve cache oluşturulma, erişilme, modification ve expiry time'larını gösteren timestamp'leri içerir.

### Cookies Management

Cookie'ler [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) kullanılarak incelenebilir. Metadata; name'leri, URL'leri, access count değerlerini ve zamanla ilgili çeşitli ayrıntıları içerir. Persistent cookie'ler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` konumunda saklanırken session cookie'leri memory'de tutulur.

### Download Details

Download metadata'sına [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) üzerinden erişilebilir. Belirli container'lar URL, file type ve download location gibi verileri içerir. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` konumunda bulunabilir.

### Browsing History

Browsing history'yi incelemek için [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir. Bunun için extracted history file'larının konumu ve Internet Explorer configuration'ı gerekir. Buradaki metadata modification ve access time'ları ile access count değerlerini içerir. History file'ları `%userprofile%\Appdata\Local\Microsoft\Windows\History` konumunda bulunur.

### Typed URLs

Typed URL'ler ve kullanım zamanları, `NTUSER.DAT` registry'sinde `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` altında saklanır. Bunlar kullanıcı tarafından girilen son 50 URL'yi ve son input time'larını takip eder.

## Microsoft Edge

Microsoft Edge, kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` konumunda saklar. Çeşitli data type'ları için path'ler şunlardır:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari verileri `/Users/$User/Library/Safari` konumunda saklanır. Önemli dosyalar şunlardır:<sup>[[3]](#references)</sup>

- **History.db**: URL'leri ve visit timestamp'lerini içeren `history_visits` ve `history_items` table'larını barındırır. Sorgulamak için `sqlite3` kullanın.
- **Downloads.plist**: Download edilen dosyalar hakkında bilgiler.
- **Bookmarks.plist**: Bookmark'lanmış URL'leri saklar.
- **TopSites.plist**: En sık ziyaret edilen siteler.
- **Extensions.plist**: Safari browser extension'larının listesi. Almak için `plutil` veya `pluginkit` kullanın.
- **UserNotificationPermissions.plist**: Push notification göndermesine izin verilen domain'ler. Parse etmek için `plutil` kullanın.
- **LastSession.plist**: Son session'daki tab'ler. Parse etmek için `plutil` kullanın.
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` kullanarak kontrol edin. 1 yanıtı, özelliğin aktif olduğunu gösterir.<sup>[[2]](#references)</sup>

## Opera

Opera'nın verileri `/Users/$USER/Library/Application Support/com.operasoftware.Opera` konumunda bulunur ve history ile downloads için Chrome'un formatını paylaşır.

- **Browser’s built-in anti-phishing**: Preferences file içindeki `fraud_protection_enabled` değerinin `true` olarak ayarlanıp ayarlanmadığını `grep` kullanarak kontrol edin.<sup>[[2]](#references)</sup>

Bu path'ler ve command'ler, farklı web browser'lar tarafından saklanan browsing data'larına erişmek ve bunları anlamak için kritik öneme sahiptir.

## References

- [1] [Web Browsers Forensics: A Guide On Doing Web Browsers Forensic Analysis](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Part 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Scripting and Analysis by Jaron Bradley](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)

{{#include ../../../banners/hacktricks-training.md}}

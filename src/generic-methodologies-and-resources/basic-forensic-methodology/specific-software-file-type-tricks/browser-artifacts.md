# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts, web tarayıcıları tarafından depolanan gezinme geçmişi, yer imleri ve cache verileri gibi çeşitli veri türlerini içerir. Bu artifacts, işletim sistemi içinde belirli klasörlerde tutulur. Konumları ve adları tarayıcılar arasında farklılık gösterse de genellikle benzer veri türlerini depolarlar.

En yaygın browser artifacts özeti:

- **Navigation History**: Kullanıcının ziyaret ettiği web sitelerini izler ve kötü amaçlı sitelere yapılan ziyaretleri belirlemek için kullanışlıdır.
- **Autocomplete Data**: Sık yapılan aramalara dayalı öneriler sunar ve navigation history ile birlikte kullanıldığında içgörü sağlar.
- **Bookmarks**: Kullanıcının hızlı erişim için kaydettiği sitelerdir.
- **Extensions and Add-ons**: Kullanıcı tarafından yüklenen browser extension veya add-on'larıdır.
- **Cache**: Web sitesi yükleme sürelerini iyileştirmek için web içeriğini (ör. görseller, JavaScript dosyaları) depolar ve forensic analysis için değerlidir.
- **Logins**: Depolanan login bilgileri.
- **Favicons**: Web siteleriyle ilişkilendirilmiş, sekmelerde ve yer imlerinde görünen simgelerdir; kullanıcı ziyaretleri hakkında ek bilgi sağlamak için kullanışlıdır.
- **Browser Sessions**: Açık browser session'larıyla ilgili verilerdir.
- **Downloads**: Browser üzerinden indirilen dosyaların kayıtlarıdır.
- **Form Data**: Web formlarına girilen ve gelecekteki otomatik doldurma önerileri için kaydedilen bilgilerdir.
- **Thumbnails**: Web sitelerinin önizleme görselleridir.
- **Custom Dictionary.txt**: Kullanıcı tarafından browser sözlüğüne eklenen kelimelerdir.

## Firefox

Firefox, kullanıcı verilerini işletim sistemine bağlı olarak belirli konumlarda depolanan profile'lar içinde düzenler:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu dizinlerin içinde bulunan `profiles.ini` dosyası, kullanıcı profile'larını listeler. Her profile ait veriler, `profiles.ini` içindeki `Path` değişkeninde belirtilen ve `profiles.ini` dosyasının bulunduğu dizinde yer alan bir klasörde depolanır. Bir profile ait klasör eksikse silinmiş olabilir.

Her profile klasörünün içinde birkaç önemli dosya bulabilirsiniz:<sup>[[1]](#references)</sup>

- **places.sqlite**: History, bookmarks ve downloads verilerini depolar. Windows üzerinde [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi araçlar history verilerine erişebilir.
- History ve downloads bilgilerini çıkarmak için belirli SQL sorgularını kullanın.
- **bookmarkbackups**: Bookmarks yedeklerini içerir.
- **formhistory.sqlite**: Web formu verilerini depolar.
- **handlers.json**: Protocol handler'larını yönetir.
- **persdict.dat**: Custom dictionary kelimelerini içerir.
- **addons.json** ve **extensions.sqlite**: Yüklü add-on ve extension'lar hakkında bilgi içerir.
- **cookies.sqlite**: Cookie depolama alanıdır; Windows üzerinde inceleme için [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) kullanılabilir.
- **cache2/entries** veya **startupCache**: [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi araçlarla erişilebilen cache verileridir.
- **favicons.sqlite**: Favicon'ları depolar.
- **prefs.js**: Kullanıcı ayarlarını ve tercihlerini içerir.
- **downloads.sqlite**: Artık places.sqlite içine entegre edilmiş eski downloads veritabanıdır.
- **thumbnails**: Web sitesi thumbnail'larını içerir.
- **logins.json**: Şifrelenmiş login bilgilerini içerir.
- **key4.db** veya **key3.db**: Hassas bilgileri korumak için kullanılan encryption key'lerini depolar.

Ayrıca, `prefs.js` içinde `browser.safebrowsing` girdilerini arayarak browser'ın anti-phishing ayarlarını kontrol edebilirsiniz. Bu girdiler, safe browsing özelliklerinin etkin veya devre dışı olduğunu gösterir.<sup>[[2]](#references)</sup>

Master password'ü decrypt etmeyi denemek için [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) kullanabilirsiniz\
Aşağıdaki script ve çağrıyla brute force yapmak için bir password dosyası belirleyebilirsiniz:
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

Google Chrome, kullanıcı profillerini işletim sistemine göre belirli konumlarda depolar:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinlerde, kullanıcı verilerinin çoğu **Default/** veya **ChromeDefaultData/** klasörlerinde bulunabilir. Aşağıdaki dosyalar önemli veriler içerir:<sup>[[1]](#references)</sup>

- **History**: URL'leri, indirmeleri ve arama anahtar kelimelerini içerir. Windows'ta geçmişi okumak için [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılabilir. "Transition Type" sütununun; kullanıcıların bağlantılara tıklaması, yazılan URL'ler, form gönderimleri ve sayfa yeniden yüklemeleri dahil olmak üzere çeşitli anlamları vardır.
- **Cookies**: Cookie'leri depolar. İnceleme için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) kullanılabilir.
- **Cache**: Önbelleğe alınmış verileri tutar. İncelemek için Windows kullanıcıları [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) kullanabilir.

Electron tabanlı masaüstü uygulamaları (ör. Discord) Chromium Simple Cache kullanır ve diskte zengin artifact'ler bırakır. Bkz.:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Kullanıcı yer imleri.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi favicon'larını depolar.
- **Login Data**: Kullanıcı adları ve parolalar gibi giriş kimlik bilgilerini içerir.
- **Current Session**/**Current Tabs**: Mevcut browsing session ve açık sekmeler hakkındaki veriler.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önce son session sırasında aktif olan siteler hakkındaki bilgiler.
- **Extensions**: Browser extensions ve eklentileri için dizinler.
- **Thumbnails**: Web sitesi küçük resimlerini depolar.
- **Preferences**: Plugin'ler, extensions, pop-up'lar, bildirimler ve daha fazlasına ilişkin ayarlar dahil olmak üzere zengin bilgiler içeren bir dosya.
- **Browser’s built-in anti-phishing**: Anti-phishing ve malware korumasının etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` komutunu çalıştırın. Çıktıda `{"enabled: true,"}` ifadesini arayın.<sup>[[2]](#references)</sup>

## **SQLite DB Veri Kurtarma**

Önceki bölümlerde gözlemleyebileceğiniz gibi Chrome ve Firefox, verileri depolamak için **SQLite** database'lerini kullanır. **Silinen girdileri** [**sqlparse**](https://github.com/padfoot999/sqlparse) **veya** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **aracını kullanarak kurtarmak** mümkündür.

## **Internet Explorer 11**

Internet Explorer 11, verilerini ve metadata'sını çeşitli konumlarda yönetir. Bu, depolanan bilgilerin ve bunlara karşılık gelen ayrıntıların kolay erişim ve yönetim için ayrılmasına yardımcı olur.

### Metadata Depolama

Internet Explorer metadata'sı `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` konumunda depolanır (VX, V01, V16 veya V24 olabilir). Bununla birlikte, `V01.log` dosyası `WebcacheVX.data` ile zaman damgası farklılıkları gösterebilir ve bu da `esentutl /r V01 /d` kullanılarak onarım yapılması gerektiğine işaret eder. Bir ESE database'inde bulunan bu metadata, sırasıyla photorec ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi araçlar kullanılarak kurtarılabilir ve incelenebilir. **Containers** tablosunda, Skype gibi diğer Microsoft araçlarına ait cache ayrıntıları da dahil olmak üzere her veri segmentinin depolandığı belirli tablolar veya container'lar belirlenebilir.

### Cache İncelemesi

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı, cache verilerinin çıkarıldığı klasör konumunu gerektirerek cache incelemesine olanak tanır. Cache metadata'sı; dosya adı, dizin, erişim sayısı, URL kaynağı ve cache oluşturma, erişim, değiştirilme ve sona erme zamanlarını belirten zaman damgalarını içerir.

### Cookies Yönetimi

Cookie'ler, adları, URL'leri, erişim sayılarını ve çeşitli zamanla ilgili ayrıntıları içeren metadata ile birlikte [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) kullanılarak incelenebilir. Kalıcı cookie'ler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` konumunda depolanırken session cookie'leri bellekte tutulur.

### İndirme Ayrıntıları

İndirme metadata'sına [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) üzerinden erişilebilir; belirli container'lar URL, dosya türü ve indirme konumu gibi verileri içerir. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` altında bulunabilir.

### Browsing History

Browsing history'yi incelemek için, çıkarılmış history dosyalarının konumu ve Internet Explorer yapılandırması gerektiren [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir. Buradaki metadata, değiştirilme ve erişim zamanlarının yanı sıra erişim sayılarını da içerir. History dosyaları `%userprofile%\Appdata\Local\Microsoft\Windows\History` konumunda bulunur.

### Yazılan URL'ler

Yazılan URL'ler ve kullanım zamanları, `NTUSER.DAT` içindeki `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` registry konumlarında depolanır; kullanıcı tarafından girilen son 50 URL ve bunların son giriş zamanları izlenir.

## Microsoft Edge

Microsoft Edge, kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` konumunda depolar. Çeşitli veri türleri için yollar şunlardır:<sup>[[1]](#references)</sup>

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari verileri `/Users/$User/Library/Safari` konumunda depolanır. Önemli dosyalar şunlardır:<sup>[[3]](#references)</sup>

- **History.db**: URL'leri ve ziyaret zaman damgalarını içeren `history_visits` ve `history_items` tablolarını barındırır. Sorgulamak için `sqlite3` kullanın.
- **Downloads.plist**: İndirilen dosyalar hakkındaki bilgiler.
- **Bookmarks.plist**: Yer imi eklenmiş URL'leri depolar.
- **TopSites.plist**: En sık ziyaret edilen siteler.
- **Extensions.plist**: Safari browser extensions listesi. Almak için `plutil` veya `pluginkit` kullanın.
- **UserNotificationPermissions.plist**: Push notification göndermesine izin verilen domain'ler. Ayrıştırmak için `plutil` kullanın.
- **LastSession.plist**: Son session'daki sekmeler. Ayrıştırmak için `plutil` kullanın.
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` kullanarak kontrol edin. `1` yanıtı özelliğin etkin olduğunu gösterir.<sup>[[2]](#references)</sup>

## Opera

Opera'nın verileri `/Users/$USER/Library/Application Support/com.operasoftware.Opera` konumunda bulunur ve history ile download'lar için Chrome'un formatını paylaşır.

- **Browser’s built-in anti-phishing**: `grep` kullanarak Preferences dosyasındaki `fraud_protection_enabled` değerinin `true` olarak ayarlanıp ayarlanmadığını kontrol ederek doğrulayın.<sup>[[2]](#references)</sup>

Bu yollar ve komutlar, farklı web browser'ları tarafından depolanan browsing data'ya erişmek ve bunları anlamak için kritik öneme sahiptir.

## References

- [1] [Web Browsers Forensics: Web Browser Forensic Analysis Yapma Rehberi](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Bölüm 3: Sistem Manipülasyonu](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Jaron Bradley Tarafından Scripting ve Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}

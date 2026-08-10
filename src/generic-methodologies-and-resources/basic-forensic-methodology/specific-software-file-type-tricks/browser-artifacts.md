# Browser Artifacts

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artifacts, web browsers tarafından depolanan gezinme geçmişi, yer imleri ve önbellek verileri gibi çeşitli veri türlerini içerir. Bu artifacts, işletim sistemi içinde belirli klasörlerde tutulur; konumları ve adları browser'lar arasında değişiklik gösterse de genellikle benzer veri türlerini depolar.

En yaygın browser artifacts özeti:

- **Gezinme Geçmişi**: Kullanıcının web sitelerini ziyaretlerini izler ve kötü amaçlı sitelere yapılan ziyaretleri belirlemek için kullanışlıdır.
- **Autocomplete Verileri**: Sık yapılan aramalara dayalı öneriler sunar ve gezinme geçmişiyle birlikte kullanıldığında faydalı bilgiler sağlar.
- **Yer İmleri**: Kullanıcı tarafından hızlı erişim için kaydedilen siteler.
- **Extensions ve Add-ons**: Kullanıcı tarafından yüklenen browser extensions veya add-ons.
- **Cache**: Web sitesi yükleme sürelerini iyileştirmek için web içeriğini (ör. görseller, JavaScript dosyaları) depolar ve forensic analysis için değerlidir.
- **Logins**: Depolanan giriş kimlik bilgileri.
- **Favicons**: Web siteleriyle ilişkilendirilen, sekmelerde ve yer imlerinde görünen simgelerdir; kullanıcı ziyaretleri hakkında ek bilgiler sağlayabilir.
- **Browser Sessions**: Açık browser session'larıyla ilgili veriler.
- **Downloads**: Browser üzerinden indirilen dosyaların kayıtları.
- **Form Data**: Web formlarına girilen ve gelecekteki otomatik doldurma önerileri için kaydedilen bilgiler.
- **Thumbnails**: Web sitelerinin önizleme görselleri.
- **Custom Dictionary.txt**: Kullanıcı tarafından browser'ın sözlüğüne eklenen kelimeler.

## Firefox

Firefox, kullanıcı verilerini işletim sistemine bağlı olarak belirli konumlarda depolanan profile'lar içinde düzenler:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu dizinlerin içinde bulunan `profiles.ini` dosyası, kullanıcı profile'larını listeler. Her profile'ın verileri, `profiles.ini` içindeki `Path` değişkeninde belirtilen ve `profiles.ini` dosyasının kendisiyle aynı dizinde bulunan bir klasörde depolanır. Bir profile'ın klasörü eksikse silinmiş olabilir.

Her profile klasörünün içinde birkaç önemli dosya bulabilirsiniz:<sup>[[1]](#references)</sup>

- **places.sqlite**: Geçmişi, yer imlerini ve downloads verilerini depolar. Windows üzerinde [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi araçlar geçmiş verilerine erişebilir.
- Geçmiş ve downloads bilgilerini çıkarmak için belirli SQL sorgularını kullanın.
- **bookmarkbackups**: Yer imlerinin yedeklerini içerir.
- **formhistory.sqlite**: Web formu verilerini depolar.
- **handlers.json**: Protocol handler'larını yönetir.
- **persdict.dat**: Custom dictionary kelimelerini içerir.
- **addons.json** ve **extensions.sqlite**: Yüklü add-on'lar ve extension'lar hakkında bilgiler.
- **cookies.sqlite**: Cookie depolama alanıdır; Windows üzerinde inceleme için [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) kullanılabilir.
- **cache2/entries** veya **startupCache**: [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi araçlarla erişilebilen cache verileri.
- **favicons.sqlite**: Favicon'ları depolar.
- **prefs.js**: Kullanıcı ayarlarını ve tercihlerini içerir.
- **downloads.sqlite**: Artık places.sqlite içine entegre edilmiş eski downloads veritabanı.
- **thumbnails**: Web sitesi thumbnail'larını içerir.
- **logins.json**: Şifrelenmiş login bilgilerini içerir.
- **key4.db** veya **key3.db**: Hassas bilgileri korumak için kullanılan encryption key'lerini depolar.

Ayrıca, `prefs.js` içinde `browser.safebrowsing` girdilerini arayarak browser'ın anti-phishing ayarlarını kontrol edebilirsiniz; bu girdiler safe browsing özelliklerinin etkin veya devre dışı olduğunu gösterir.<sup>[[2]](#references)</sup>

Master password'ü decrypt etmeyi denemek için [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) kullanabilirsiniz\
Aşağıdaki script ve çağrıyla brute force için bir password dosyası belirleyebilirsiniz:
```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
echo "Trying $pass"
echo "$pass" | python firefox_decrypt.py
done < $passfile
```
![Tarayıcı Artifact'ları - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome, işletim sistemine göre kullanıcı profillerini belirli konumlarda depolar:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinlerde, kullanıcı verilerinin çoğu **Default/** veya **ChromeDefaultData/** klasörlerinde bulunabilir. Aşağıdaki dosyalar önemli verileri içerir:<sup>[[1]](#references)</sup>

- **History**: URL'leri, indirmeleri ve arama anahtar kelimelerini içerir. Windows'ta geçmişi okumak için [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılabilir. "Transition Type" sütununun kullanıcıların bağlantılara tıklaması, yazılan URL'ler, form gönderimleri ve sayfa yeniden yüklemeleri gibi çeşitli anlamları vardır.
- **Cookies**: Cookie'leri depolar. İnceleme için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) kullanılabilir.
- **Cache**: Önbelleğe alınan verileri tutar. İncelemek için Windows kullanıcıları [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) aracını kullanabilir.

Electron tabanlı masaüstü uygulamaları (ör. Discord) da Chromium Simple Cache kullanır ve diskte zengin artifact'lar bırakır. Bkz.:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Kullanıcı yer imleri.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi favicon'larını depolar.
- **Login Data**: Kullanıcı adları ve parolalar gibi oturum açma kimlik bilgilerini içerir.
- **Current Session**/**Current Tabs**: Geçerli tarama oturumu ve açık sekmeler hakkındaki veriler.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önce son oturum sırasında etkin olan siteler hakkındaki bilgiler.
- **Extensions**: Browser extension'ları ve eklentileri için dizinler.
- **Thumbnails**: Web sitesi küçük resimlerini depolar.
- **Preferences**: Plugin'ler, extension'lar, pop-up'lar, bildirimler ve daha fazlasına ilişkin ayarlar dahil olmak üzere zengin bilgiler içeren bir dosya.
- **Browser’s built-in anti-phishing**: Anti-phishing ve malware korumasının etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` komutunu çalıştırın. Çıktıda `{"enabled: true,"}` ifadesini arayın.<sup>[[2]](#references)</sup>

## **SQLite DB Data Recovery**

Önceki bölümlerde görebileceğiniz gibi Chrome ve Firefox, verileri depolamak için **SQLite** veritabanlarını kullanır. Silinmiş girdileri [**sqlparse**](https://github.com/padfoot999/sqlparse) **veya** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **aracını kullanarak kurtarmak** mümkündür.

## **Internet Explorer 11**

Internet Explorer 11, verilerini ve metadata'sını çeşitli konumlarda yönetir; bu da depolanan bilgilerin ve bunlara karşılık gelen ayrıntıların kolay erişim ve yönetim için ayrılmasına yardımcı olur.

### Metadata Storage

Internet Explorer metadata'sı `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` konumunda depolanır (VX, V01, V16 veya V24 olabilir). Buna eşlik eden `V01.log` dosyası, `WebcacheVX.data` ile modifikasyon zamanı tutarsızlıkları gösterebilir ve bu da `esentutl /r V01 /d` kullanılarak onarım yapılması gerektiğine işaret eder. Bir ESE veritabanında bulunan bu metadata, photorec ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi araçlar kullanılarak sırasıyla kurtarılabilir ve incelenebilir. **Containers** tablosunda, Skype gibi diğer Microsoft araçlarına ait cache ayrıntıları da dahil olmak üzere her veri segmentinin depolandığı belirli tablolar veya container'lar belirlenebilir.

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı, cache incelemesine olanak tanır ve cache verilerinin çıkarılacağı klasörün konumunu gerektirir. Cache metadata'sı dosya adını, dizini, erişim sayısını, URL kaynağını ve cache'in oluşturulma, erişilme, değiştirilme ve sona erme zamanlarını gösteren zaman damgalarını içerir.

### Cookies Management

Cookie'ler [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) kullanılarak incelenebilir. Metadata; adları, URL'leri, erişim sayılarını ve zamanla ilgili çeşitli ayrıntıları içerir. Kalıcı cookie'ler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` konumunda depolanırken oturum cookie'leri bellekte tutulur.

### Download Details

İndirme metadata'sına [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) üzerinden erişilebilir. Belirli container'lar URL, dosya türü ve indirme konumu gibi verileri içerir. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` altında bulunabilir.

### Browsing History

Tarama geçmişini incelemek için [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir. Bunun için çıkarılmış geçmiş dosyalarının konumu ve Internet Explorer yapılandırması gerekir. Buradaki metadata; modifikasyon ve erişim zamanlarının yanı sıra erişim sayılarını da içerir. Geçmiş dosyaları `%userprofile%\Appdata\Local\Microsoft\Windows\History` konumunda bulunur.

### Typed URLs

Yazılan URL'ler ve kullanım zamanları, `NTUSER.DAT` içindeki `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` registry anahtarlarında depolanır. Bu anahtarlar, kullanıcı tarafından girilen son 50 URL'yi ve bunların son giriş zamanlarını takip eder.

## Microsoft Edge

Microsoft Edge, kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` konumunda depolar. Çeşitli veri türlerine ait yollar şunlardır:<sup>[[1]](#references)</sup>

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
- **Extensions.plist**: Safari browser extension'larının listesi. Almak için `plutil` veya `pluginkit` kullanın.
- **UserNotificationPermissions.plist**: Push notification göndermesine izin verilen domain'ler. Ayrıştırmak için `plutil` kullanın.
- **LastSession.plist**: Son oturumdaki sekmeler. Ayrıştırmak için `plutil` kullanın.
- **Browser’s built-in anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` komutunu kullanarak kontrol edin. 1 yanıtı, özelliğin etkin olduğunu gösterir.<sup>[[2]](#references)</sup>

## Opera

Opera'nın verileri `/Users/$USER/Library/Application Support/com.operasoftware.Opera` konumunda bulunur ve geçmiş ile indirmeler için Chrome'un formatını paylaşır.

- **Browser’s built-in anti-phishing**: Preferences dosyasındaki `fraud_protection_enabled` değerinin `true` olarak ayarlanıp ayarlanmadığını `grep` kullanarak kontrol edin.<sup>[[2]](#references)</sup>

Bu yollar ve komutlar, farklı web browser'ları tarafından depolanan tarama verilerine erişmek ve bunları anlamak için kritik öneme sahiptir.

## References

- [1] [Web Browser Forensics: Web Browser Forensic Analysis Yapma Rehberi](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Incident Response | Bölüm 3: System Manipulation](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Incident Response: Jaron Bradley tarafından Scripting ve Analysis](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}

# Tarayıcı Artifaktları

{{#include ../../../banners/hacktricks-training.md}}

## Tarayıcı Artifaktları <a href="#id-3def" id="id-3def"></a>

Tarayıcı artifaktları, gezinme geçmişi, yer imleri ve önbellek verileri gibi web tarayıcıları tarafından saklanan çeşitli veri türlerini içerir. Bu artifaktlar işletim sistemi içinde belirli klasörlerde tutulur; tarayıcıya göre konum ve isimler değişse de genelde benzer veri türlerini depolarlar.

En yaygın tarayıcı artifaktlarının bir özeti:

- **Gezinme Geçmişi**: Kullanıcının ziyaret ettiği siteleri izler; kötü amaçlı sitelere yapılan ziyaretleri belirlemede faydalıdır.
- **Otomatik Doldurma Verileri**: Sık yapılan aramalara dayalı öneriler; gezinme geçmişi ile birleştirildiğinde içgörü sağlar.
- **Yer İmleri**: Kullanıcının hızlı erişim için kaydettiği siteler.
- **Eklentiler ve Add-on'lar**: Kullanıcının yüklediği tarayıcı eklentileri veya add-on'lar.
- **Önbellek**: Web içeriğini (ör. resimler, JavaScript dosyaları) saklayarak site yükleme sürelerini iyileştirir; adli analiz için değerlidir.
- **Giriş Bilgileri**: Saklanan oturum açma kimlik bilgileri.
- **Favikonlar**: Sekelerde ve yer imlerinde görünen site ikonları; kullanıcı ziyaretleri hakkında ek bilgi sağlar.
- **Tarayıcı Oturumları**: Açık tarayıcı oturumlarıyla ilgili veriler.
- **İndirilenler**: Tarayıcı üzerinden indirilen dosyaların kayıtları.
- **Form Verileri**: Web formlarına girilen bilgiler; gelecekte otomatik doldurma önerileri için saklanır.
- **Küçük Resimler (Thumbnails)**: Web sitelerinin önizleme görüntüleri.
- **Custom Dictionary.txt**: Kullanıcının tarayıcının sözlüğüne eklediği kelimeler.

## Firefox

Firefox, kullanıcı verilerini profiller içinde düzenler; bu profiller işletim sistemine bağlı olarak belirli konumlarda saklanır:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu dizinler içinde yer alan `profiles.ini` dosyası kullanıcı profillerini listeler. Her profilin verileri, `profiles.ini` içindeki `Path` değişkeninde belirtilen isimdeki bir klasörde tutulur; bu klasör `profiles.ini` ile aynı dizinde bulunur. Bir profil klasörü eksikse, silinmiş olabilir.

Her profil klasöründe bulunabilecek bazı önemli dosyalar:

- **places.sqlite**: Geçmiş, yer imleri ve indirilenleri saklar. Windows'ta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi araçlar geçmiş verilerine erişebilir.
- Geçmiş ve indirilenler bilgilerini çıkarmak için belirli SQL sorguları kullanın.
- **bookmarkbackups**: Yer imi yedeklerini içerir.
- **formhistory.sqlite**: Web formu verilerini saklar.
- **handlers.json**: Protokol işleyicilerini yönetir.
- **persdict.dat**: Özel sözlük kelimeleri.
- **addons.json** ve **extensions.sqlite**: Yüklü add-on ve eklentilerle ilgili bilgiler.
- **cookies.sqlite**: Çerez depolaması; Windows'ta inceleme için [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) mevcuttur.
- **cache2/entries** veya **startupCache**: Önbellek verileri; [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi araçlarla erişilebilir.
- **favicons.sqlite**: Favikonları saklar.
- **prefs.js**: Kullanıcı ayarları ve tercihleri.
- **downloads.sqlite**: Eski indirme veritabanı, artık places.sqlite ile entegredir.
- **thumbnails**: Web sitesi küçük resimleri.
- **logins.json**: Şifrelenmiş giriş bilgileri.
- **key4.db** veya **key3.db**: Hassas bilgileri korumak için şifreleme anahtarlarını saklar.

Ayrıca, tarayıcının anti-phishing ayarlarını kontrol etmek için `prefs.js` içinde `browser.safebrowsing` girdilerinin aranması, güvenli gezinme özelliklerinin etkin olup olmadığını gösterir.

Ana şifreyi çözmeyi denemek için şu adresi kullanabilirsiniz: https://github.com/unode/firefox_decrypt\
Aşağıdaki script ve çağrı ile kırma işlemi için bir parola dosyası belirtebilirsiniz:
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

Google Chrome, kullanıcı profillerini işletim sistemine göre şu konumlarda depolar:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinlerin içinde, çoğu kullanıcı verisi **Default/** veya **ChromeDefaultData/** klasörlerinde bulunur. Aşağıdaki dosyalar önemli veriler içerir:

- **History**: URL'leri, indirmeleri ve arama anahtar kelimelerini içerir. Windows'ta geçmişi okumak için [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılabilir. "Transition Type" sütunu, linklere kullanıcı tıklamaları, yazılan URL'ler, form gönderimleri ve sayfa yenilemeleri gibi çeşitli anlamlara sahiptir.
- **Cookies**: Çerezleri depolar. İnceleme için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) mevcuttur.
- **Cache**: Önbelleğe alınmış verileri tutar. İncelemek için Windows kullanıcıları [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) kullanabilir.
  
Electron tabanlı masaüstü uygulamaları (ör. Discord) da Chromium Simple Cache kullanır ve disk üzerinde zengin artefaktlar bırakır. Bakınız:

{{#ref}}
discord-cache-forensics.md
{{#endref}}
- **Bookmarks**: Kullanıcı yer imleri.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi favicon'larını depolar.
- **Login Data**: Kullanıcı adları ve parolalar gibi giriş bilgilerini içerir.
- **Current Session**/**Current Tabs**: Mevcut tarayıcı oturumu ve açık sekmeler hakkında veri.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önceki son oturumda aktif olan sitelerle ilgili bilgiler.
- **Extensions**: Tarayıcı eklentileri ve addon'lar için dizinler.
- **Thumbnails**: Web sitesi küçük resimlerini depolar.
- **Preferences**: Eklentiler, uzantılar, açılır pencereler, bildirimler ve daha fazlası için ayarları içeren bilgi açısından zengin bir dosya.
- **Browser’s built-in anti-phishing**: Anti-phishing ve kötü amaçlı yazılım korumasının etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` çalıştırın. Çıktıda `{"enabled: true,"}` arayın.

## **SQLite DB Data Recovery**

Önceki bölümlerde görebileceğiniz gibi, hem Chrome hem de Firefox verileri depolamak için **SQLite** veritabanlarını kullanır. Silinmiş kayıtları kurtarmak için [**sqlparse**](https://github.com/padfoot999/sqlparse) veya [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) araçları kullanılabilir.

## **Internet Explorer 11**

Internet Explorer 11, verilerini ve meta verilerini çeşitli konumlarda yönetir; bu da saklanan bilgiler ile ilgili ayrıntıların ayrıştırılmasını ve erişimini kolaylaştırır.

### Metadata Storage

Internet Explorer için meta veriler `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` içinde saklanır (VX V01, V16 veya V24 olabilir). Buna ek olarak, `V01.log` dosyası `WebcacheVX.data` ile zaman damgası uyumsuzlukları gösterebilir; bu durumda `esentutl /r V01 /d` ile onarım gerekebilir. Bu meta veriler, bir ESE veritabanında tutulur ve photorec ile kurtarılabilir, [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) ile incelenebilir. **Containers** tablosunda, her veri bölümünün hangi tablo veya konteynerde saklandığı, ayrıca Skype gibi diğer Microsoft araçlarının önbellek ayrıntıları görülebilir.

### Cache Inspection

Önbelleği incelemek için [IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı kullanılabilir; bunun için önbellek verilerinin çıkarıldığı klasörün konumu gereklidir. Önbellek meta verileri dosya adı, dizin, erişim sayısı, URL kaynağı ve önbellek oluşturma, erişim, değiştirme ve sona erme zamanlarını içerir.

### Cookies Management

Çerezler [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) ile incelenebilir; meta veriler isimler, URL'ler, erişim sayıları ve çeşitli zaman bilgilerini kapsar. Kalıcı çerezler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` içinde saklanırken, oturum çerezleri bellekte tutulur.

### Download Details

İndirme meta verilerine [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) üzerinden ulaşılabilir; belirli konteynerler URL, dosya türü ve indirme konumu gibi verileri tutar. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` altında bulunabilir.

### Browsing History

Tarama geçmişini gözden geçirmek için [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir; bunun için çıkarılmış geçmiş dosyalarının konumu ve Internet Explorer yapılandırması gereklidir. Buradaki meta veriler değiştirme ve erişim zamanlarını ile erişim sayısını içerir. Geçmiş dosyaları `%userprofile%\Appdata\Local\Microsoft\Windows\History` yolunda yer alır.

### Typed URLs

Yazılan URL'ler ve kullanım zamanları, kayıt defterinde `NTUSER.DAT` altında `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` yollarında saklanır; bu kayıtlar kullanıcının girilen son 50 URL'sini ve son giriş zamanlarını takip eder.

## Microsoft Edge

Microsoft Edge kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` içinde saklar. Çeşitli veri türleri için yollar:

- **Profile Path**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **History, Cookies, and Downloads**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Settings, Bookmarks, and Reading List**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Cache**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Last Active Sessions**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari verileri `/Users/$User/Library/Safari` altında saklanır. Önemli dosyalar şunlardır:

- **History.db**: `history_visits` ve `history_items` tablolarını içerir; URL'ler ve ziyaret zaman damgaları buradadır. Sorgulamak için `sqlite3` kullanın.
- **Downloads.plist**: İndirilen dosyalar hakkında bilgi.
- **Bookmarks.plist**: Yer işaretlenen URL'leri depolar.
- **TopSites.plist**: En sık ziyaret edilen siteler.
- **Extensions.plist**: Safari tarayıcı uzantıları listesi. Erişim için `plutil` veya `pluginkit` kullanın.
- **UserNotificationPermissions.plist**: Bildirim göndermesine izin verilen alan adları. `plutil` ile ayrıştırın.
- **LastSession.plist**: Son oturumdan sekmeler. `plutil` ile ayrıştırın.
- **Browser’s built-in anti-phishing**: Kontrol etmek için `defaults read com.apple.Safari WarnAboutFraudulentWebsites` komutunu kullanın. Çıktı 1 ise özellik etkin demektir.

## Opera

Opera verileri `/Users/$USER/Library/Application Support/com.operasoftware.Opera` içinde bulunur ve geçmiş ile indirmeler için Chrome ile aynı formatı paylaşır.

- **Browser’s built-in anti-phishing**: Preferences dosyasında `fraud_protection_enabled` değerinin `true` olarak ayarlanıp ayarlanmadığını `grep` ile kontrol edin.

Bu yollar ve komutlar, farklı web tarayıcıları tarafından saklanan tarama verilerine erişmek ve bunları anlamak için kritik öneme sahiptir.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**


{{#include ../../../banners/hacktricks-training.md}}

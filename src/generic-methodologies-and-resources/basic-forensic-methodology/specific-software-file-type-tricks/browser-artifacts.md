# Tarayıcı Artifaktları

{{#include ../../../banners/hacktricks-training.md}}

## Tarayıcı Artifaktları <a href="#id-3def" id="id-3def"></a>

Tarayıcı artifaktları, web tarayıcıları tarafından saklanan çeşitli veri türlerini içerir; bunlar arasında gezinme geçmişi, yer imleri ve önbellek verileri bulunur. Bu artifaktlar, işletim sistemi içinde belirli klasörlerde saklanır, konum ve isim açısından tarayıcılar arasında farklılık gösterir, ancak genellikle benzer veri türlerini depolar.

En yaygın tarayıcı artifaktlarının bir özeti:

- **Geçmiş**: Kullanıcıların web sitelerine yaptığı ziyaretleri takip eder, kötü niyetli sitelere yapılan ziyaretleri belirlemek için faydalıdır.
- **Otomatik Tamamlama Verileri**: Sık yapılan aramalara dayalı öneriler, gezinme geçmişi ile birleştirildiğinde içgörüler sunar.
- **Yer İmleri**: Kullanıcı tarafından hızlı erişim için kaydedilen siteler.
- **Eklentiler ve Ekstralar**: Kullanıcı tarafından yüklenen tarayıcı eklentileri veya ekstraları.
- **Önbellek**: Web içeriğini (örneğin, resimler, JavaScript dosyaları) saklar, web sitesi yükleme sürelerini iyileştirir, adli analiz için değerlidir.
- **Girişler**: Saklanan giriş kimlik bilgileri.
- **Favikonlar**: Web siteleriyle ilişkili simgeler, sekmelerde ve yer imlerinde görünür, kullanıcı ziyaretleri hakkında ek bilgi sağlar.
- **Tarayıcı Oturumları**: Açık tarayıcı oturumlarıyla ilgili veriler.
- **İndirmeler**: Tarayıcı üzerinden indirilen dosyaların kayıtları.
- **Form Verileri**: Web formlarına girilen bilgiler, gelecekteki otomatik doldurma önerileri için saklanır.
- **Küçük Resimler**: Web sitelerinin önizleme resimleri.
- **Custom Dictionary.txt**: Kullanıcı tarafından tarayıcının sözlüğüne eklenen kelimeler.

## Firefox

Firefox, kullanıcı verilerini profiller içinde düzenler, bu profiller işletim sistemine bağlı olarak belirli konumlarda saklanır:

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu dizinlerdeki `profiles.ini` dosyası, kullanıcı profillerini listeler. Her profilin verileri, `profiles.ini` içindeki `Path` değişkeninde belirtilen bir klasörde saklanır ve bu klasör `profiles.ini` ile aynı dizindedir. Eğer bir profilin klasörü eksikse, silinmiş olabilir.

Her profil klasöründe, birkaç önemli dosya bulabilirsiniz:

- **places.sqlite**: Geçmiş, yer imleri ve indirmeleri saklar. Windows'ta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi araçlar geçmiş verilerine erişebilir.
- Geçmiş ve indirme bilgilerini çıkarmak için belirli SQL sorguları kullanın.
- **bookmarkbackups**: Yer imlerinin yedeklerini içerir.
- **formhistory.sqlite**: Web form verilerini saklar.
- **handlers.json**: Protokol yöneticilerini yönetir.
- **persdict.dat**: Özel sözlük kelimeleri.
- **addons.json** ve **extensions.sqlite**: Yüklenen eklentiler ve uzantılar hakkında bilgi.
- **cookies.sqlite**: Çerez depolama, Windows'ta inceleme için [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) mevcuttur.
- **cache2/entries** veya **startupCache**: Önbellek verileri, [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi araçlar aracılığıyla erişilebilir.
- **favicons.sqlite**: Favikonları saklar.
- **prefs.js**: Kullanıcı ayarları ve tercihleri.
- **downloads.sqlite**: Eski indirme veritabanı, artık places.sqlite içine entegre edilmiştir.
- **thumbnails**: Web sitesi küçük resimleri.
- **logins.json**: Şifrelenmiş giriş bilgileri.
- **key4.db** veya **key3.db**: Hassas bilgileri güvence altına almak için şifreleme anahtarlarını saklar.

Ayrıca, tarayıcının anti-fishing ayarlarını kontrol etmek için `prefs.js` içinde `browser.safebrowsing` girdilerini arayarak güvenli tarama özelliklerinin etkin veya devre dışı olup olmadığını belirleyebilirsiniz.

Ana şifreyi çözmeye çalışmak için [https://github.com/unode/firefox_decrypt](https://github.com/unode/firefox_decrypt) kullanabilirsiniz.\
Aşağıdaki script ve çağrı ile bir şifre dosyasını brute force yapmak için belirtebilirsiniz:
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

Google Chrome, kullanıcı profillerini işletim sistemine bağlı olarak belirli konumlarda saklar:

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinler içinde, çoğu kullanıcı verisi **Default/** veya **ChromeDefaultData/** klasörlerinde bulunabilir. Aşağıdaki dosyalar önemli veriler içerir:

- **History**: URL'ler, indirmeler ve arama anahtar kelimelerini içerir. Windows'ta, [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılarak geçmiş okunabilir. "Transition Type" sütunu, kullanıcıların bağlantılara tıklamaları, yazılan URL'ler, form gönderimleri ve sayfa yenilemeleri gibi çeşitli anlamlar taşır.
- **Cookies**: Çerezleri saklar. İnceleme için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) mevcuttur.
- **Cache**: Önbelleğe alınmış verileri tutar. İncelemek için, Windows kullanıcıları [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) kullanabilir.
- **Bookmarks**: Kullanıcı yer imleri.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi favicon'larını saklar.
- **Login Data**: Kullanıcı adları ve şifreler gibi giriş bilgilerini içerir.
- **Current Session**/**Current Tabs**: Mevcut tarayıcı oturumu ve açık sekmeler hakkında veri.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önceki son oturumda aktif olan siteler hakkında bilgi.
- **Extensions**: Tarayıcı uzantıları ve eklentileri için dizinler.
- **Thumbnails**: Web sitesi küçük resimlerini saklar.
- **Preferences**: Eklentiler, uzantılar, açılır pencereler, bildirimler ve daha fazlası için ayarları içeren bilgi zengini bir dosya.
- **Browser’ın yerleşik anti-phishing**: Anti-phishing ve kötü amaçlı yazılım korumasının etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` komutunu çalıştırın. Çıktıda `{"enabled: true,"}` arayın.

## **SQLite DB Veri Kurtarma**

Önceki bölümlerde gözlemlediğiniz gibi, hem Chrome hem de Firefox **SQLite** veritabanlarını veri saklamak için kullanır. **Silinmiş girişleri kurtarmak için** [**sqlparse**](https://github.com/padfoot999/sqlparse) **veya** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **aracını kullanmak mümkündür.**

## **Internet Explorer 11**

Internet Explorer 11, verilerini ve meta verilerini çeşitli konumlarda yönetir, bu da saklanan bilgilerin ve ilgili detayların kolay erişim ve yönetim için ayrılmasına yardımcı olur.

### Meta Veri Saklama

Internet Explorer için meta veriler `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` içinde saklanır (VX V01, V16 veya V24 olabilir). Bununla birlikte, `V01.log` dosyası `WebcacheVX.data` ile değişiklik zamanı tutarsızlıklarını gösterebilir ve bu, `esentutl /r V01 /d` kullanarak onarım gerektirdiğini gösterir. Bu meta veriler, bir ESE veritabanında yer alır ve photorec ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi araçlar kullanılarak kurtarılabilir ve incelenebilir. **Containers** tablosunda, her veri segmentinin saklandığı belirli tablolar veya konteynerler, diğer Microsoft araçları için önbellek detayları da dahil olmak üzere, belirlenebilir.

### Önbellek İncelemesi

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı, önbellek incelemesi için kullanılabilir ve önbellek verisi çıkarım klasör konumunu gerektirir. Önbellek için meta veriler, dosya adı, dizin, erişim sayısı, URL kaynağı ve önbellek oluşturma, erişim, değiştirme ve sona erme zamanlarını gösteren zaman damgalarını içerir.

### Çerez Yönetimi

Çerezler, [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) kullanılarak incelenebilir ve meta veriler isimler, URL'ler, erişim sayıları ve çeşitli zamanla ilgili detayları kapsar. Kalıcı çerezler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` içinde saklanırken, oturum çerezleri bellekte bulunur.

### İndirme Detayları

İndirme meta verileri [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) aracılığıyla erişilebilir ve belirli konteynerler URL, dosya türü ve indirme konumu gibi verileri tutar. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` altında bulunabilir.

### Tarayıcı Geçmişi

Tarayıcı geçmişini gözden geçirmek için [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir ve çıkarılan geçmiş dosyalarının konumunu ve Internet Explorer için yapılandırmayı gerektirir. Buradaki meta veriler, değişiklik ve erişim zamanlarını, ayrıca erişim sayısını içerir. Geçmiş dosyaları `%userprofile%\Appdata\Local\Microsoft\Windows\History` içinde yer alır.

### Yazılan URL'ler

Yazılan URL'ler ve kullanım zamanları, `NTUSER.DAT` içinde `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` altında saklanır ve kullanıcının girdiği son 50 URL ve son giriş zamanlarını takip eder.

## Microsoft Edge

Microsoft Edge, kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` içinde saklar. Çeşitli veri türleri için yollar:

- **Profil Yolu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geçmiş, Çerezler ve İndirmeler**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ayarlar, Yer İmleri ve Okuma Listesi**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Önbellek**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Son Aktif Oturumlar**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari verileri `/Users/$User/Library/Safari` içinde saklanır. Ana dosyalar şunlardır:

- **History.db**: `history_visits` ve `history_items` tablolarını içerir ve URL'ler ile ziyaret zaman damgalarını barındırır. Sorgulamak için `sqlite3` kullanın.
- **Downloads.plist**: İndirilen dosyalar hakkında bilgi.
- **Bookmarks.plist**: Yerleştirilen URL'leri saklar.
- **TopSites.plist**: En sık ziyaret edilen siteler.
- **Extensions.plist**: Safari tarayıcı uzantılarının listesi. Almak için `plutil` veya `pluginkit` kullanın.
- **UserNotificationPermissions.plist**: Bildirim göndermeye izin verilen alanlar. Ayrıştırmak için `plutil` kullanın.
- **LastSession.plist**: Son oturumdan sekmeler. Ayrıştırmak için `plutil` kullanın.
- **Browser’ın yerleşik anti-phishing**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` kullanarak kontrol edin. 1 yanıtı, özelliğin aktif olduğunu gösterir.

## Opera

Opera'nın verileri `/Users/$USER/Library/Application Support/com.operasoftware.Opera` içinde yer alır ve geçmiş ile indirmeler için Chrome'un formatını paylaşır.

- **Browser’ın yerleşik anti-phishing**: `Preferences` dosyasında `fraud_protection_enabled` değerinin `true` olarak ayarlandığını kontrol ederek doğrulayın.

Bu yollar ve komutlar, farklı web tarayıcıları tarafından saklanan tarayıcı verilerine erişim ve anlama açısından kritik öneme sahiptir.

## References

- [https://nasbench.medium.com/web-browsers-forensics-7e99940c579a](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file](https://books.google.com/books?id=jfMqCgAAQBAJ&pg=PA128&lpg=PA128&dq=%22This+file)
- **Book: OS X Incident Response: Scripting and Analysis By Jaron Bradley pag 123**

{{#include ../../../banners/hacktricks-training.md}}

# Tarayıcı Artifaktları

{{#include ../../../banners/hacktricks-training.md}}

## Tarayıcı Artifaktları <a href="#id-3def" id="id-3def"></a>

Tarayıcı artifaktları; gezinme geçmişi, yer işaretleri ve cache verileri gibi web tarayıcılarında depolanan çeşitli veri türlerini içerir. Bu artifaktlar işletim sistemi içindeki belirli klasörlerde tutulur. Konumları ve adları tarayıcıya göre değişse de genellikle benzer veri türlerini depolarlar.

En yaygın tarayıcı artifaktlarının özeti:

- **Gezinme Geçmişi**: Kullanıcının ziyaret ettiği web sitelerini kaydeder; kötü amaçlı sitelere yapılan ziyaretleri belirlemeye yardımcı olur.
- **Otomatik Tamamlama Verileri**: Sık yapılan aramalara dayalı öneriler sunar; gezinme geçmişiyle birlikte incelendiğinde bilgi sağlayabilir.
- **Yer İşaretleri**: Kullanıcının hızlı erişim için kaydettiği siteler.
- **Uzantılar ve Eklentiler**: Kullanıcının yüklediği tarayıcı uzantıları veya eklentileri.
- **Cache**: Web sitesi yükleme sürelerini iyileştirmek için web içeriğini (ör. görseller, JavaScript dosyaları) depolar ve adli analiz açısından değerli olabilir.
- **Giriş Bilgileri**: Depolanan giriş kimlik bilgileri.
- **Favicon'lar**: Web siteleriyle ilişkilendirilmiş, sekmelerde ve yer işaretlerinde görünen simgeler; kullanıcı ziyaretleri hakkında ek bilgi sağlayabilir.
- **Tarayıcı Oturumları**: Açık tarayıcı oturumlarıyla ilgili veriler.
- **İndirilenler**: Tarayıcı üzerinden indirilen dosyaların kayıtları.
- **Form Verileri**: Web formlarına girilen ve gelecekte otomatik doldurma önerileri için kaydedilen bilgiler.
- **Küçük Resimler**: Web sitelerinin önizleme görselleri.
- **Custom Dictionary.txt**: Kullanıcının tarayıcı sözlüğüne eklediği kelimeler.

## Firefox

Firefox, kullanıcı verilerini işletim sistemine bağlı olarak belirli konumlarda saklanan profiller içinde düzenler:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu dizinlerdeki `profiles.ini` dosyası, kullanıcı profillerini listeler. Her profilin verileri, `profiles.ini` dosyasıyla aynı dizindeki `profiles.ini` dosyasının `Path` değişkeninde belirtilen adla bir klasörde saklanır. Bir profil klasörü eksikse silinmiş olabilir.

Her profil klasöründe birkaç önemli dosya bulabilirsiniz:<sup>[[1]](#references)</sup>

- **places.sqlite**: Geçmişi, yer işaretlerini ve indirilenleri depolar. Windows'taki [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi araçlar geçmiş verilerine erişebilir.
  - Geçmiş ve indirilenler bilgilerini çıkarmak için belirli SQL sorguları kullanın.
- **bookmarkbackups**: Yer işaretlerinin yedeklerini içerir.
- **formhistory.sqlite**: Web formu verilerini depolar.
- **handlers.json**: Protokol işleyicilerini yönetir.
- **persdict.dat**: Özel sözlük kelimelerini içerir.
- **addons.json** ve **extensions.sqlite**: Yüklenen eklentiler ve uzantılar hakkındaki bilgileri içerir.
- **cookies.sqlite**: Cookie'leri depolar; Windows'ta inceleme için [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) kullanılabilir.
- **cache2/entries** veya **startupCache**: Cache verilerini içerir; [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi araçlarla erişilebilir.
- **favicons.sqlite**: Favicon'ları depolar.
- **prefs.js**: Kullanıcı ayarlarını ve tercihlerini içerir.
- **downloads.sqlite**: Eski indirme veritabanıdır; artık places.sqlite dosyasına entegre edilmiştir.
- **thumbnails**: Web sitesi küçük resimlerini içerir.
- **logins.json**: Şifrelenmiş giriş bilgilerini içerir.
- **key4.db** veya **key3.db**: Hassas bilgileri korumak için kullanılan şifreleme anahtarlarını depolar.

Ayrıca, `prefs.js` dosyasında `browser.safebrowsing` girdilerini arayarak tarayıcının kimlik avına karşı koruma ayarlarını kontrol edebilirsiniz. Bu girdiler, güvenli gezinme özelliklerinin etkin mi devre dışı mı olduğunu gösterir.<sup>[[2]](#references)</sup>

Erişilebilir bir profildeki kayıtlı giriş bilgilerini çözmek için, yapılandırılmışsa [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins) sağlanmalı veya ayrıca kurtarılmalıdır; profil bu parolayı göstermez. Kurtarılan giriş bilgilerinin web hesabında kimlik doğrulaması sağladığını doğrulayın. Unix root erişimi için, kimlik bilgilerinin Unix kimlik doğrulaması tarafından root kullanıcısı için de kabul edildiğine dair ayrıca kanıt gerekir. Kayıtlı giriş bilgilerini [firefox_decrypt](https://github.com/unode/firefox_decrypt) ile inceleyebilirsiniz. Aşağıdaki örnek, parola dosyasındaki olası Primary Password değerlerini dener:

```bash:brute.sh
#!/bin/bash

#./brute.sh top-passwords.txt 2>/dev/null | grep -A2 -B2 "chrome:"
passfile=$1
while read pass; do
  echo "Trying $pass"
  echo "$pass" | python firefox_decrypt.py
done < $passfile
```

![Tarayıcı Artefaktları - Firefox: echo "$pass" | python firefox decrypt.py](<../../../images/image (692).png>)

## Google Chrome

Google Chrome, kullanıcı profillerini işletim sistemine bağlı olarak belirli konumlarda saklar:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinlerde, kullanıcı verilerinin çoğu **Default/** veya **ChromeDefaultData/** klasörlerinde bulunabilir. Aşağıdaki dosyalar önemli veriler içerir:<sup>[[1]](#references)</sup>

- **History**: URL’leri, indirmeleri ve arama anahtar kelimelerini içerir. Windows’ta geçmişi okumak için [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılabilir. "Transition Type" sütunu; bağlantılara kullanıcı tıklamaları, yazılan URL’ler, form gönderimleri ve sayfa yenilemeleri gibi çeşitli anlamlara gelir.
- **Cookies**: Çerezleri saklar. İnceleme için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) kullanılabilir.
- **Cache**: Önbelleğe alınan verileri tutar. Windows kullanıcıları inceleme için [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) aracını kullanabilir.

  Electron tabanlı masaüstü uygulamaları (ör. Discord) da Chromium Simple Cache kullanır ve diskte zengin artefaktlar bırakır. Bkz.:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Kullanıcı yer işaretleri.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi favicon’larını saklar.
- **Login Data**: Kullanıcı adları ve parolalar gibi oturum açma kimlik bilgilerini içerir.
- **Current Session**/**Current Tabs**: Geçerli tarama oturumu ve açık sekmeler hakkındaki veriler.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önceki son oturum sırasında etkin olan sitelere ilişkin bilgiler.
- **Extensions**: Tarayıcı uzantıları ve eklentileri için dizinler.
- **Thumbnails**: Web sitesi küçük resimlerini saklar.
- **Preferences**: Eklentiler, uzantılar, açılır pencereler, bildirimler ve daha fazlasına ilişkin ayarlar dahil, zengin bilgiler içeren bir dosya.
- **Tarayıcının yerleşik kimlik avı koruması**: Kimlik avı ve kötü amaçlı yazılım korumasının etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` komutunu çalıştırın. Çıktıda `{"enabled: true,"}` ifadesini arayın.<sup>[[2]](#references)</sup>

Bir Chromium profilindeki `Local Extension Settings/<extension-id>/` dizini, parola yöneticilerinin anahtar materyali dahil olmak üzere uzantıya özgü durumu içerebilir. Örneğin, [Passbolt şifrelenmiş özel anahtarının tarayıcı uzantısının yerel depolama alanında tutulduğunu belirtir](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/) ve ilgili dizini [Chrome uzantı kimliği](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) belirler. Dizinin mevcut olması tek başına anahtarın orada bulunduğunu kanıtlamaz veya bir kasanın kilidini açmaz: kullanıcının profil verilerine, kullanılabilir bir özel anahtara ve parolaya, ayrıca sunucu için yetkili bir kurtarma/kimlik doğrulama yoluna erişimi olmalıdır. Bir kasa öğesi işletim sistemi hesabı parolası içeriyorsa, hesabın yeniden kullanılıp kullanılmadığı ayrıca doğrulanmalıdır. Rutin envanter çıkarma işlemlerinde LevelDB dosyalarının veya gizli değerlerin dökümünü almak yerine yalnızca depolama yolu raporlanmalıdır.

## **SQLite DB Data Recovery**

Önceki bölümlerde görebileceğiniz gibi, hem Chrome hem de Firefox verileri depolamak için **SQLite** veritabanlarını kullanır. Silinen girdileri [**sqlparse**](https://github.com/padfoot999/sqlparse) **veya** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **aracını kullanarak kurtarmak** mümkündür.

## **Internet Explorer 11**

Internet Explorer 11, verilerini ve meta verilerini çeşitli konumlarda yöneterek saklanan bilgilerin ve bu bilgilere karşılık gelen ayrıntıların kolayca erişilip yönetilebilmesi için bunları birbirinden ayırır.

### Metadata Storage

Internet Explorer meta verileri `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` konumunda saklanır (VX, V01, V16 veya V24 olabilir). Buna eşlik eden `V01.log` dosyasının değiştirilme zamanı, `WebcacheVX.data` dosyasınınkiyle uyuşmayabilir; bu durumda `esentutl /r V01 /d` kullanılarak onarım gerekebilir. Bir ESE veritabanında bulunan bu meta veriler, sırasıyla photorec ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi araçlarla kurtarılıp incelenebilir. **Containers** tablosu, Skype gibi diğer Microsoft araçlarının önbellek ayrıntıları dahil, her veri segmentinin saklandığı tabloları veya kapsayıcıları belirlemeye yardımcı olur.

### Cache Inspection

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı, önbelleğin incelenmesini sağlar ve önbellek verilerinin çıkarıldığı klasörün konumunu gerektirir. Önbellek meta verileri; dosya adını, dizini, erişim sayısını, URL kaynağını ve önbelleğin oluşturulma, erişilme, değiştirilme ve sona erme zamanlarını gösteren zaman damgalarını içerir.

### Cookies Management

Çerezler [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) kullanılarak incelenebilir. Meta veriler; adları, URL’leri, erişim sayılarını ve çeşitli zaman bilgilerini içerir. Kalıcı çerezler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` konumunda saklanırken oturum çerezleri bellekte tutulur.

### Download Details

İndirme meta verilerine [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) aracılığıyla erişilebilir. Belirli kapsayıcılar URL, dosya türü ve indirme konumu gibi verileri içerir. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` konumunda bulunabilir.

### Browsing History

Tarama geçmişini incelemek için, çıkarılmış geçmiş dosyalarının konumunu belirtip Internet Explorer için yapılandırma yaparak [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir. Buradaki meta veriler, erişim sayılarının yanı sıra değiştirilme ve erişim zamanlarını içerir. Geçmiş dosyaları `%userprofile%\Appdata\Local\Microsoft\Windows\History` konumunda bulunur.

### Typed URLs

Yazılan URL’ler ve bunların kullanım zamanları, kayıt defterindeki `NTUSER.DAT` dosyasında `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` altında saklanır. Bu kayıtlar, kullanıcının girdiği son 50 URL’yi ve bunların en son girilme zamanlarını izler.

## Microsoft Edge

Microsoft Edge, kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` konumunda saklar. Çeşitli veri türlerinin yolları şöyledir:<sup>[[1]](#references)</sup>

- **Profil Yolu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geçmiş, Çerezler ve İndirmeler**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ayarlar, Yer İşaretleri ve Okuma Listesi**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Önbellek**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Son Etkin Oturumlar**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari verileri `/Users/$User/Library/Safari` konumunda saklanır. Önemli dosyalar şunlardır:<sup>[[3]](#references)</sup>

- **History.db**: URL’leri ve ziyaret zaman damgalarını içeren `history_visits` ve `history_items` tablolarını barındırır. Sorgulamak için `sqlite3` kullanın.
- **Downloads.plist**: İndirilen dosyalar hakkındaki bilgiler.
- **Bookmarks.plist**: Yer işaretlerine eklenmiş URL’leri saklar.
- **TopSites.plist**: En sık ziyaret edilen siteler.
- **Extensions.plist**: Safari tarayıcı uzantılarının listesi. Listeyi almak için `plutil` veya `pluginkit` kullanın.
- **UserNotificationPermissions.plist**: Anlık bildirim göndermesine izin verilen etki alanları. Ayrıştırmak için `plutil` kullanın.
- **LastSession.plist**: Son oturumdaki sekmeler. Ayrıştırmak için `plutil` kullanın.
- **Tarayıcının yerleşik kimlik avı koruması**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` komutuyla kontrol edin. 1 yanıtı, özelliğin etkin olduğunu gösterir.<sup>[[2]](#references)</sup>

## Opera

Opera verileri `/Users/$USER/Library/Application Support/com.operasoftware.Opera` konumunda bulunur ve geçmiş ile indirmeler için Chrome ile aynı biçimi kullanır.

- **Tarayıcının yerleşik kimlik avı koruması**: Preferences dosyasındaki `fraud_protection_enabled` değerinin `true` olarak ayarlanıp ayarlanmadığını `grep` kullanarak kontrol edin.<sup>[[2]](#references)</sup>

Bu yollar ve komutlar, farklı web tarayıcılarında saklanan tarama verilerine erişmek ve bu verileri anlamak için çok önemlidir.

## References

- [1] [Web Tarayıcıları Adli İncelemesi: Web Tarayıcılarında Adli Analiz Yapma Rehberi](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Olay Müdahalesi | Bölüm 3: Sistem Manipülasyonu](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Olay Müdahalesi: Jaron Bradley’nin Betik Yazımı ve Analiz Çalışması](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}

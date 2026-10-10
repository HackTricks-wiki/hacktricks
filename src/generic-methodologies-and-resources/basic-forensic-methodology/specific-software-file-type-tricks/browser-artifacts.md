# Browser Artifacts

{{#include ../../../banners/hacktricks-training.md}}

## Browser Artifacts <a href="#id-3def" id="id-3def"></a>

Browser artefaktları; gezinme geçmişi, yer imleri ve önbellek verileri gibi web browser'ları tarafından saklanan çeşitli veri türlerini içerir. Bu artefaktlar, işletim sistemi içinde belirli klasörlerde tutulur. Konumları ve adları browser'lara göre değişse de genellikle benzer veri türlerini saklarlar.

En yaygın browser artefaktlarının özeti:

- **Gezinme Geçmişi**: Kullanıcının ziyaret ettiği web sitelerini takip eder; kötü amaçlı sitelere yapılan ziyaretleri belirlemek için yararlıdır.
- **Otomatik Tamamlama Verileri**: Sık yapılan aramalara dayalı öneriler sunar; gezinme geçmişiyle birlikte incelendiğinde bilgi sağlayabilir.
- **Yer İmleri**: Kullanıcının hızlı erişim için kaydettiği siteler.
- **Uzantılar ve Eklentiler**: Kullanıcının yüklediği browser uzantıları veya eklentileri.
- **Önbellek**: Web sitesi yükleme sürelerini iyileştirmek için web içeriğini (ör. görseller, JavaScript dosyaları) saklar; adli analiz için değerlidir.
- **Oturum Açma Bilgileri**: Saklanan oturum açma kimlik bilgileri.
- **Favicons**: Sekmelerde ve yer imlerinde görünen, web siteleriyle ilişkili simgeler; kullanıcı ziyaretleri hakkında ek bilgi sağlayabilir.
- **Browser Oturumları**: Açık browser oturumlarıyla ilgili veriler.
- **İndirilenler**: Browser üzerinden indirilen dosyaların kayıtları.
- **Form Verileri**: Web formlarına girilen ve gelecekte otomatik doldurma önerileri için kaydedilen bilgiler.
- **Küçük Resimler**: Web sitelerinin önizleme görselleri.
- **Custom Dictionary.txt**: Kullanıcının browser sözlüğüne eklediği kelimeler.

## Firefox

Firefox, kullanıcı verilerini işletim sistemine bağlı olarak belirli konumlarda saklanan profiller içinde düzenler:<sup>[[1]](#references)</sup>

- **Linux**: `~/.mozilla/firefox/`
- **MacOS**: `/Users/$USER/Library/Application Support/Firefox/Profiles/`
- **Windows**: `%userprofile%\AppData\Roaming\Mozilla\Firefox\Profiles\`

Bu dizinlerdeki `profiles.ini` dosyası, kullanıcı profillerini listeler. Her profilin verileri, `profiles.ini` ile aynı dizinde bulunan `profiles.ini` dosyasındaki `Path` değişkeninde belirtilen klasörde saklanır. Bir profilin klasörü yoksa silinmiş olabilir.

Her profil klasöründe birkaç önemli dosya bulunur:<sup>[[1]](#references)</sup>

- **places.sqlite**: Geçmişi, yer imlerini ve indirilenleri saklar. Windows'ta [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) gibi araçlar geçmiş verilerine erişebilir.
  - Geçmiş ve indirilenler bilgilerini çıkarmak için belirli SQL sorgularını kullanın.
- **bookmarkbackups**: Yer imi yedeklerini içerir.
- **formhistory.sqlite**: Web formu verilerini saklar.
- **handlers.json**: Protokol işleyicilerini yönetir.
- **persdict.dat**: Özel sözlük kelimeleri.
- **addons.json** ve **extensions.sqlite**: Yüklü eklentiler ve uzantılar hakkındaki bilgiler.
- **cookies.sqlite**: Cookie'leri saklar; Windows'ta inceleme için [MZCookiesView](https://www.nirsoft.net/utils/mzcv.html) kullanılabilir.
- **cache2/entries** veya **startupCache**: Önbellek verileri; [MozillaCacheView](https://www.nirsoft.net/utils/mozilla_cache_viewer.html) gibi araçlarla erişilebilir.
- **favicons.sqlite**: Favicon'ları saklar.
- **prefs.js**: Kullanıcı ayarları ve tercihleri.
- **downloads.sqlite**: Eski indirme veritabanı; artık places.sqlite ile bütünleşiktir.
- **thumbnails**: Web sitesi küçük resimleri.
- **logins.json**: Şifrelenmiş oturum açma bilgileri.
- **key4.db** veya **key3.db**: Hassas bilgileri korumak için kullanılan şifreleme anahtarlarını saklar.

Ayrıca, `prefs.js` dosyasında `browser.safebrowsing` girdilerini arayarak browser'ın kimlik avına karşı koruma ayarlarını kontrol edebilirsiniz. Bu girdiler, güvenli gezinme özelliklerinin etkin mi yoksa devre dışı mı olduğunu gösterir.<sup>[[2]](#references)</sup>

Erişilebilir bir profildeki kayıtlı oturum açma bilgilerini çözmek için, yapılandırılmışsa [Firefox Primary Password](https://support.mozilla.org/en-US/kb/use-primary-password-protect-stored-logins) sağlanmalı veya ayrı olarak kurtarılmalıdır; profil bu parolayı açığa çıkarmaz. Kurtarılan oturum açma bilgilerinin ilgili web hesabında kimlik doğrulaması sağladığını doğrulayın. Unix root erişimi için, kimlik bilgisinin Unix kimlik doğrulamasında root için de kabul edildiğine dair ayrıca kanıt gerekir. Kayıtlı oturum açma bilgilerini [firefox_decrypt](https://github.com/unode/firefox_decrypt) ile inceleyebilirsiniz. Aşağıdaki örnek, parola dosyasındaki olası Primary Password değerlerini dener:

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

Google Chrome, kullanıcı profillerini işletim sistemine göre belirli konumlarda saklar:<sup>[[1]](#references)</sup>

- **Linux**: `~/.config/google-chrome/`
- **Windows**: `C:\Users\XXX\AppData\Local\Google\Chrome\User Data\`
- **MacOS**: `/Users/$USER/Library/Application Support/Google/Chrome/`

Bu dizinlerdeki kullanıcı verilerinin çoğu **Default/** veya **ChromeDefaultData/** klasörlerinde bulunabilir. Aşağıdaki dosyalar önemli veriler içerir:<sup>[[1]](#references)</sup>

- **History**: URL'leri, indirmeleri ve arama anahtar kelimelerini içerir. Windows'ta geçmişi okumak için [ChromeHistoryView](https://www.nirsoft.net/utils/chrome_history_view.html) kullanılabilir. "Transition Type" sütununun; bağlantılara kullanıcı tıklamaları, yazılan URL'ler, form gönderimleri ve sayfa yeniden yüklemeleri gibi çeşitli anlamları vardır.
- **Cookies**: Çerezleri saklar. İnceleme için [ChromeCookiesView](https://www.nirsoft.net/utils/chrome_cookies_view.html) kullanılabilir.
- **Cache**: Önbelleğe alınan verileri tutar. Windows kullanıcıları inceleme için [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) kullanabilir.

  Electron tabanlı masaüstü uygulamaları (ör. Discord) da Chromium Simple Cache kullanır ve diskte zengin artefaktlar bırakır. Bkz.:

  {{#ref}}
  discord-cache-forensics.md
  {{#endref}}
- **Bookmarks**: Kullanıcı yer işaretleri.
- **Web Data**: Form geçmişini içerir.
- **Favicons**: Web sitesi favicon'larını saklar.
- **Login Data**: Kullanıcı adları ve parolalar gibi oturum açma kimlik bilgilerini içerir.
- **Current Session**/**Current Tabs**: Geçerli tarama oturumu ve açık sekmeler hakkındaki veriler.
- **Last Session**/**Last Tabs**: Chrome kapatılmadan önceki son oturumda etkin olan siteler hakkındaki bilgiler.
- **Extensions**: Tarayıcı uzantıları ve eklentileri için dizinler.
- **Thumbnails**: Web sitesi küçük resimlerini saklar.
- **Preferences**: Eklenti ve uzantı ayarları, açılır pencereler, bildirimler ve daha fazlası gibi zengin bilgiler içeren bir dosya.
- **Tarayıcının yerleşik kimlik avı önleme özelliği**: Kimlik avı ve kötü amaçlı yazılım korumasının etkin olup olmadığını kontrol etmek için `grep 'safebrowsing' ~/Library/Application Support/Google/Chrome/Default/Preferences` komutunu çalıştırın. Çıktıda `{"enabled: true,"}` ifadesini arayın.<sup>[[2]](#references)</sup>

Bir Chromium profilinin `Local Extension Settings/<extension-id>/` dizini, parola yöneticisi anahtar materyali de dahil olmak üzere uzantıya özgü durum verilerini barındırabilir. Örneğin [Passbolt, şifrelenmiş özel anahtarının tarayıcı uzantısının yerel depolama alanında tutulduğunu belirtir](https://www.passbolt.com/docs/user/faq/why-a-browser-extension/) ve [Chrome uzantısı kimliği](https://chromewebstore.google.com/detail/passbolt-open-source-pass/didegimhafipceonhjepacocaffmoppf) ilgili dizini belirler. Dizinin varlığı tek başına anahtarın orada olduğunu kanıtlamaz veya bir vault'un kilidini açmaz: kullanıcının profil verilerine, kullanılabilir bir özel anahtara ve parolaya, ayrıca sunucu için yetkili bir kurtarma/kimlik doğrulama yoluna erişimi olmalıdır. Bir vault öğesi işletim sistemi hesabının parolasını içeriyorsa, hesabın başka yerlerde yeniden kullanılıp kullanılmadığı ayrıca doğrulanmalıdır. Rutin numaralandırma işlemlerinde yalnızca depolama yolu bildirilmelidir; LevelDB dosyalarının veya gizli değerlerin dökümü alınmamalıdır.

## **SQLite DB Veri Kurtarma**

Önceki bölümlerde görebileceğiniz gibi, hem Chrome hem de Firefox verileri depolamak için **SQLite** veritabanları kullanır. **Silinmiş girdileri**, [**sqlparse**](https://github.com/padfoot999/sqlparse) **veya** [**sqlparse_gui**](https://github.com/mdegrazia/SQLite-Deleted-Records-Parser/releases) **aracını kullanarak kurtarmak** mümkündür.

## **Internet Explorer 11**

Internet Explorer 11, verilerini ve meta verilerini çeşitli konumlarda yöneterek depolanan bilgilerin ve bunlara karşılık gelen ayrıntıların kolayca erişilip yönetilebilmesi için ayrılmasını sağlar.

### Meta Veri Depolama

Internet Explorer meta verileri `%userprofile%\Appdata\Local\Microsoft\Windows\WebCache\WebcacheVX.data` konumunda saklanır (VX, V01, V16 veya V24 olabilir). Bu dosyaya eşlik eden `V01.log` dosyasının değiştirilme zamanı, `WebcacheVX.data` dosyasının zamanıyla uyuşmayabilir; bu durum `esentutl /r V01 /d` kullanılarak onarım yapılması gerektiğini gösterebilir. Bir ESE veritabanında tutulan bu meta veriler, sırasıyla photorec ve [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) gibi araçlarla kurtarılıp incelenebilir. **Containers** tablosunda, önbellek ayrıntıları da dahil olmak üzere her veri segmentinin depolandığı belirli tablolar veya kapsayıcılar görülebilir. Bu ayrıntılar Skype gibi diğer Microsoft araçlarına ait olabilir.

### Önbellek İncelemesi

[IECacheView](https://www.nirsoft.net/utils/ie_cache_viewer.html) aracı, önbellek verilerinin çıkarıldığı klasörün konumunu gerektirerek önbelleğin incelenmesini sağlar. Önbellek meta verileri; dosya adı, dizin, erişim sayısı, URL kaynağı ve önbelleğin oluşturulma, erişilme, değiştirilme ve sona erme zamanlarını belirten zaman damgalarını içerir.

### Çerez Yönetimi

Çerezler [IECookiesView](https://www.nirsoft.net/utils/iecookies.html) kullanılarak incelenebilir. Meta veriler; adları, URL'leri, erişim sayılarını ve çeşitli zaman bilgilerini içerir. Kalıcı çerezler `%userprofile%\Appdata\Roaming\Microsoft\Windows\Cookies` konumunda saklanırken oturum çerezleri bellekte tutulur.

### İndirme Ayrıntıları

İndirme meta verilerine [ESEDatabaseView](https://www.nirsoft.net/utils/ese_database_view.html) aracılığıyla erişilebilir. Belirli kapsayıcılar URL, dosya türü ve indirme konumu gibi verileri tutar. Fiziksel dosyalar `%userprofile%\Appdata\Roaming\Microsoft\Windows\IEDownloadHistory` konumunda bulunabilir.

### Tarama Geçmişi

Tarama geçmişini incelemek için [BrowsingHistoryView](https://www.nirsoft.net/utils/browsing_history_view.html) kullanılabilir. Bunun için çıkarılan geçmiş dosyalarının konumu belirtilmeli ve Internet Explorer için yapılandırma yapılmalıdır. Bu meta veriler, erişim sayılarının yanı sıra değiştirilme ve erişilme zamanlarını da içerir. Geçmiş dosyaları `%userprofile%\Appdata\Local\Microsoft\Windows\History` konumunda bulunur.

### Yazılan URL'ler

Yazılan URL'ler ve bunların kullanım zamanları, kayıt defterinde `NTUSER.DAT` altında `Software\Microsoft\InternetExplorer\TypedURLs` ve `Software\Microsoft\InternetExplorer\TypedURLsTime` konumlarında saklanır. Bu kayıtlar, kullanıcının girdiği son 50 URL'yi ve bunların son girilme zamanlarını izler.

## Microsoft Edge

Microsoft Edge kullanıcı verilerini `%userprofile%\Appdata\Local\Packages` konumunda saklar. Çeşitli veri türlerinin yolları şöyledir:<sup>[[1]](#references)</sup>

- **Profil Yolu**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC`
- **Geçmiş, Çerezler ve İndirmeler**: `C:\Users\XX\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat`
- **Ayarlar, Yer İşaretleri ve Okuma Listesi**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\DataStore\Data\nouser1\XXX\DBStore\spartan.edb`
- **Önbellek**: `C:\Users\XXX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC#!XXX\MicrosoftEdge\Cache`
- **Son Etkin Oturumlar**: `C:\Users\XX\AppData\Local\Packages\Microsoft.MicrosoftEdge_XXX\AC\MicrosoftEdge\User\Default\Recovery\Active`

## Safari

Safari verileri `/Users/$User/Library/Safari` konumunda saklanır. Önemli dosyalar şunlardır:<sup>[[3]](#references)</sup>

- **History.db**: URL'leri ve ziyaret zaman damgalarını içeren `history_visits` ve `history_items` tablolarını barındırır. Sorgulamak için `sqlite3` kullanın.
- **Downloads.plist**: İndirilen dosyalar hakkındaki bilgiler.
- **Bookmarks.plist**: Yer işareti olarak kaydedilen URL'leri saklar.
- **TopSites.plist**: En sık ziyaret edilen siteler.
- **Extensions.plist**: Safari tarayıcı uzantılarının listesi. Listeyi almak için `plutil` veya `pluginkit` kullanın.
- **UserNotificationPermissions.plist**: Anlık bildirim göndermesine izin verilen etki alanları. Ayrıştırmak için `plutil` kullanın.
- **LastSession.plist**: Son oturumdaki sekmeler. Ayrıştırmak için `plutil` kullanın.
- **Tarayıcının yerleşik kimlik avı önleme özelliği**: `defaults read com.apple.Safari WarnAboutFraudulentWebsites` komutuyla kontrol edin. 1 yanıtı, özelliğin etkin olduğunu gösterir.<sup>[[2]](#references)</sup>

## Opera

Opera verileri `/Users/$USER/Library/Application Support/com.operasoftware.Opera` konumunda bulunur ve geçmiş ile indirmeler için Chrome'un kullandığı biçimi kullanır.

- **Tarayıcının yerleşik kimlik avı önleme özelliği**: `grep` kullanarak Preferences dosyasındaki `fraud_protection_enabled` değerinin `true` olarak ayarlanıp ayarlanmadığını kontrol edin.<sup>[[2]](#references)</sup>

Bu yollar ve komutlar, farklı web tarayıcılarında saklanan tarama verilerine erişmek ve bunları anlamak için önemlidir.

## References

- [1] [Web Tarayıcılarının Adli İncelemesi: Web Tarayıcılarında Adli Analiz Yapma Rehberi](https://nasbench.medium.com/web-browsers-forensics-7e99940c579a)
- [2] [macOS Olay Müdahalesi | Bölüm 3: Sistem Manipülasyonu](https://www.sentinelone.com/labs/macos-incident-response-part-3-system-manipulation/)
- [3] [OS X Olay Müdahalesi: Jaron Bradley'den Betik Yazımı ve Analiz](https://books.google.com/books?id=jfMqCgAAQBAJ\&pg=PA128\&lpg=PA128\&dq=%22This+file)
{{#include ../../../banners/hacktricks-training.md}}

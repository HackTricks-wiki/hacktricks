# macOS Dosya Uzantısı ve URL Şeması Uygulama İşleyicileri

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Veritabanı

Bu veritabanı, macOS'te yüklü tüm uygulamaları içerir. Yüklü her uygulama hakkında desteklenen **URL şemaları**, **belge türleri**, **UTI'ler** ve varsayılan işleyiciler gibi bilgiler almak için sorgulanabilir.

Bu veritabanını şu komutla dökmek mümkündür:

```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```

Ya da [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) aracını kullanarak.

**`/usr/libexec/lsd`**, veritabanının beynidir. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` ve daha fazlası gibi **çeşitli XPC servisleri** sağlar. Ancak MIME türleri veya URL scheme’leri için varsayılan uygulamaları değiştiren `.launchservices.changedefaulthandler` ya da `.launchservices.changeurlschemehandler` gibi dışa açılan XPC işlevlerini kullanabilmeleri için uygulamalardan **bazı entitlements** da ister.

**`/System/Library/CoreServices/launchservicesd`**, `com.apple.coreservices.launchservicesd` servisini üstlenir ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı **`/usr/bin/lsappinfo`** veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) kullanılarak sorgulanabilir.

Operatör açısından genellikle **iki yararlı görünüm** olduğunu unutmayın:

- LaunchServices / `lsd` tarafından yönetilen kayıt veritabanı (`.csstore` dosyalarıyla desteklenir).
- `LSHandlers` dizisi içindeki `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` dosyasında saklanan kullanıcı başına geçerli varsayılanlar.

Bu ayrım önemlidir: Bir uygulama, bir türü veya scheme’i işleyebilecek şekilde **kayıtlı** olabilir; ancak **geçerli varsayılan** yine de başka bir bundle ID olabilir.

Yeni macOS sürümlerinde uygulamaların keşfi `/Applications` ile sınırlı değildir: Spotlight tarafından görülebilen, erişilebilir diğer klasörlerdeki ve bağlanmış/paylaşılan birimlerdeki uygulamalar da kayıt defterine eklenebilir. Bu nedenle, inceleme sırasında `lsregister -dump` çıktısındaki `path` ve birim bilgilerini koruyun; uygulama paketi keşfedilebilir durumda kaldığı sürece kaydının silinmesinin kalıcı olacağını varsaymayın.<sup>[[4]](#references)</sup>

## Dosya uzantısı ve URL scheme uygulama işleyicileri

Aşağıdaki satır, uzantıya bağlı olarak hangi uygulamaların dosyaları açabildiğini bulmak için yararlı olabilir:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```

Veya [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) gibi bir şey kullanın:

```bash
./swda getSchemes #Get all the available schemes
./swda getApps #Get all the apps declared
./swda getUTIs #Get all the UTIs
./swda getHandler --URL ftp #Get ftp handler
```

Bir uygulamanın desteklediği uzantıları şu şekilde de kontrol edebilirsiniz:

```bash
cd /Applications/Safari.app/Contents
grep -A3 CFBundleTypeExtensions Info.plist  | grep string
				<string>css</string>
				<string>pdf</string>
				<string>webarchive</string>
				<string>webbookmark</string>
				<string>webhistory</string>
				<string>webloc</string>
				<string>download</string>
				<string>safariextz</string>
				<string>gif</string>
				<string>html</string>
				<string>htm</string>
				<string>js</string>
				<string>jpg</string>
				<string>jpeg</string>
				<string>jp2</string>
				<string>txt</string>
				<string>text</string>
				<string>png</string>
				<string>tiff</string>
				<string>tif</string>
				<string>url</string>
				<string>ico</string>
				<string>xhtml</string>
				<string>xht</string>
				<string>xml</string>
				<string>xbl</string>
				<string>svg</string>
```

## Etkin işleyicileri listeleme

**Mevcut kullanıcının varsayılanları** için genellikle en kullanışlı dosya şudur:

```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```

Bundan **URL scheme** işleyicilerinin dökümünü almak için:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerURLScheme != null) |
      {scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

**content-type / UTI** handler'larını dump etmek için:

```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
  jq '.[] | select(.LSHandlerContentType != null) |
      {uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```

Örnek bir dosyanın UTI ağacını çözümlemek için:

```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```

Varsayılanları sorgulamak veya değiştirmek için daha kullanıcı dostu bir CLI istiyorsanız:

```bash
# Classic tool
# https://github.com/moretension/duti
duti -x jpg                    # Show current default for extension
duti -s com.apple.Safari public.html all
duti -s com.apple.Finder ftp   # Set default for ftp://

# Newer tool
# https://github.com/jackchuka/dutix
dutix targets show public.html
dutix targets show ftp
dutix apps show Safari
```

### Dosya başına `Open With` geçersiz kılmaları

İşleyici çözümlemesinde **dosyaya özgü** bir katman da bulunur. LaunchServices, dosyanın UTI'sine ve kullanıcının genel varsayılanına başvurmadan önce `com.apple.LaunchServices.OpenWith` genişletilmiş özniteliğini denetler. Finder, tek bir dosya için **Always Open With** seçildiğinde bu özniteliği oluşturur; özniteliğin değeri uygulama yolunu, bundle identifier'ı ve sürüm seçicisini içeren bir ikili property list'tir.<sup>[[3]](#references)</sup>

Dosya uzantısına güvenmeden bunu inceleyip çözümleyin:

```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```

Bu, `duti`, `dutix` veya `LSHandlers` zararsız bir genel varsayılan gösterdiği hâlde tek bir lure beklenmedik bir uygulamayla açılıyorsa işe yarar. Kontrollü bir lab ortamında, Finder üzerinden yapılandırılmış bir dosyadan tam opak değer kopyalanabilir; bu değeri silmek, normal tür tabanlı çözümlemeyi geri getirir:

```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```

## İlginç Info.plist anahtarları

Bir uygulama paketini incelerken şu anahtarlar en önemlileridir:

- **`CFBundleDocumentTypes`**: paketin açabildiğini belirttiği belge grupları.
- **`LSItemContentTypes`**: belge türlerini UTI'lere bağlamanın **modern / tercih edilen** yolu.
- **`LSHandlerRank`**: LaunchServices tarafından kullanılan sıralama (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: uygulamanın desteklediği özel URI şemaları.
- **`UTExportedTypeDeclarations`**: uygulamanın **sahip olduğu** UTI'ler.
- **`UTImportedTypeDeclarations`**: uygulamanın sahip olmadığı ancak sistemin tanımasını istediği UTI'ler.

Hızlı inceleme için kullanışlı bir komut:

```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
  rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```

İnce ama önemli bir ayrıntı: **`LSItemContentTypes`** varsa, **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** ve **`CFBundleTypeOSTypes`** gibi eski anahtarlar temelde eski uyumluluk verileridir. Gerçek handler çözümlemesi için öncelikle UTI yoluna odaklanın.

## Offensive notes

Uygulamaların handler talepleri ilgi çekici hâle gelmeden önce çalışması gerekmez; ancak **tek başına bir `.app` bundle yazmak, hemen kaydedilmesini garanti etmez**. Finder, bir uygulamayı keşfettiğinde, buna kullanıcının klasörüne göz atması da dahil olmak üzere, kaydedebilir; kayıt işlemi açılışta veya oturum açıldığında ya da açık bir kayıt çağrısı aracılığıyla da gerçekleşebilir. Bir talebi test etmeden önce `lsregister -dump` çıktısını kontrol edin. Kayıt işlemi tek başına uygulamayı başlatmaz veya onu etkin varsayılan hâle getirmez.<sup>[[5]](#references)</sup> Kalıcılık önkoşulları için bkz. [URL Scheme & File-Type Handlers](../macos-auto-start-locations.md#url-scheme--file-type-handlers-launchservices).

Bu, hem **persistence / hijacking araştırmaları** hem de **initial-access zincirleri** için kullanışlıdır:

- Kötü amaçlı bir uygulama, **nadir bir uzantıyı** veya **özel bir UTI**'yi sahiplenip kurbanın yem dosyasını açmasını bekleyebilir.
- Kötü amaçlı bir uygulama; tarayıcı, Electron uygulaması, Office belgesi, sohbet istemcisi veya başka bir yardımcı uygulama üzerinden erişilebilen **özel bir URL scheme** kaydedebilir.<sup>[[1]](#references)</sup>
- Normal varsayılan çözümlemeyi belirli bir aday handler'ı test etmekten ayırmak için, scheme'i LaunchServices üzerinden `open 'targetscheme://host/path?value=test'` ile çağırın; ardından belirli bir kayıtlı bundle'ı hedeflemek için `open -b com.vendor.Target 'targetscheme://host/path?value=test'` komutunu kullanın. Bu, alıcı uygulamanın saldırgan denetimindeki URL bileşenlerini nasıl doğruladığını ve çözdüğünü denetlemek için kullanışlıdır.<sup>[[1]](#references)</sup>
- Bir uygulama bundle'ını oluşturduktan sonra düzenlerseniz LaunchServices'ı yeniden ayrıştırmaya zorlamak için şunu kullanabilirsiniz:

```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```

Şüpheli bundle'ları test ederken özellikle şunlara dikkat edin:

- Yaygın olmayan türlerde **`LSHandlerRank=Owner`**.
- Birçok uzantıyı talep eden geniş **`CFBundleDocumentTypes`** dizileri.
- İlginç davranışları yalnızca bir document veya URI handler arkasında bulunan **helper / wrapper uygulamaları**.
- LaunchServices'e yönlendirme yapan **kısayol benzeri dosyalar** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` tarzı numaralar ve ilgili Gatekeeper açıları için [bu diğer sayfaya](macos-security-protections/macos-fs-tricks/README.md) bakın.<sup>[[2]](#references)</sup>

### Alt seçeneklere iletilen URL parametreleri

Bir tarayıcının harici protokol onayı yalnızca handler'ı açmayı onaylar; URL parametrelerini güvenilir kılmaz. Alıcı uygulamanın URL parser'ından başlayarak kullanılan herhangi bir library, media engine, helper process veya file-writing seçeneğine kadar iz sürün. URL alanlarını alt seçenek adlarına dönüştüren bir query-key prefix arayın. Zararsız bir marker ile, geçici bir hesapta hem literal hem de percent-encoded ayraçları test edin.<sup>[[6]](#references)</sup>

Yalnızca uygulamanın ilk parsing işlemini değil, alt bileşenin **kabul ettiği nihai seçeneği** doğrulayın. Bir handler, prefix içeren query key'lerin mpv input commands'a ulaşmasına izin veriyordu; bu seçeneğin engellenmesi yine de bir file-write yolu bırakıyordu. Yalnızca bilinen tek bir tehlikeli key'i değil, erişilebilir seçenek sınıfını test edin.<sup>[[7]](#references)</sup>

### Yerleşik `applescript://` handler'ı

`applescript://com.apple.scripteditor` URL handler'ı `action=new` ve URL-encoded bir `script` parametresini kabul eder. Bu nedenle bir tarayıcı bağlantısı, Terminal'e yapıştırma adımını atlayarak Script Editor'ü saldırganın kontrolündeki AppleScript editörde hazır olacak şekilde açabilir. Bu **otomatik çalıştırma değildir**: tarayıcı Script Editor'ü açmak için sorabilir ve kullanıcının script'i çalıştırması gerekir.<sup>[[8]](#references)</sup>

Yeni macOS sürümleri bir script-document uyarısı gösterebilir; ayrıca XProtect, AppleScript'i çalıştırma sırasında tarar.<sup>[[8]](#references)[[9]](#references)</sup>

Değerlendirilen macOS sürümünde handler'ı ve uyarıları kontrol etmek için zararsız bir yerel probe kullanın; **Run** tıklanana kadar yalnızca editörü doldurmalıdır.<sup>[[8]](#references)</sup>

```bash
open 'applescript://com.apple.scripteditor?action=new&script=display%20dialog%20%22handler%20probe%22'
```

Pasif code-execution hedefiniz yalnızca bir klasöre göz atmakla veya bir dosya seçmekle tetikleniyorsa, farklı ancak yakından ilişkili bir file-handler yüzeyi olan [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) için ayrılmış sayfayı da inceleyin.



## References

- [1] [Objective-See - Özel URL Schemes üzerinden Uzaktan Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gatekeeper'ı aşmak: macOS'taki Gatekeeper açıklarına daha yakından bakış](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS bir dosyayı doğru uygulamada nasıl açar?](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia'da LaunchServices'i yönetmek](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
- [5] [Apple - Launch Services Kavramları](https://developer.apple.com/library/archive/documentation/Carbon/Conceptual/LaunchServicesConcepts/LSCConcepts/LSCConcepts.html)
- [6] [stackpointer - IINA URL scheme komut yürütme araştırması](https://binary.stackpointer.re/iina-142-url-scheme-command-execution)
- [7] [IINA - URL scheme'de mpv options'ın güvenli olmayan şekilde işlenmesi](https://github.com/iina/iina/security/advisories/GHSA-w5xh-98j7-jp5q)
- [8] [Jamf Threat Labs - ClickFix tekniği Terminal yerine Script Editor kullanıyor](https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/)
- [9] [Apple - Terminal ve script korumaları](https://support.apple.com/en-ie/guide/security/sece3b202c4b/web)
{{#include ../../banners/hacktricks-training.md}}

# macOS Dosya Uzantısı ve URL scheme app handlers

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Bu, macOS'te yüklü olan tüm uygulamaların bulunduğu ve her yüklü uygulama hakkında desteklenen **URL schemes**, **document types**, **UTIs** ve varsayılan handler'lar gibi bilgileri almak için sorgulanabilen bir database'dir.

Bu database'i şu şekilde dump etmek mümkündür:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) aracını kullanabilirsiniz.

**`/usr/libexec/lsd`**, veritabanının beynidir. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` ve daha fazlası gibi **birkaç XPC service** sağlar. Ancak açığa çıkarılan XPC işlevlerini kullanabilmeleri için uygulamalara bazı **entitlements** verilmesini de **gerektirir**. Örneğin `.launchservices.changedefaulthandler` veya `.launchservices.changeurlschemehandler`, MIME türleri ya da URL scheme'leri için varsayılan uygulamaları değiştirmek amacıyla kullanılır.

**`/System/Library/CoreServices/launchservicesd`**, `com.apple.coreservices.launchservicesd` service'ini kaydeder ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı **`/usr/bin/lsappinfo`** veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ile sorgulanabilir.

Bir operator açısından genellikle **iki kullanışlı görünüm** olduğunu unutmayın:

- LaunchServices / `lsd` tarafından yönetilen **registration database** (`.csstore` dosyalarıyla desteklenir).
- `LSHandlers` array'i içinde `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` konumunda saklanan **kullanıcı bazında etkin varsayılanlar**.

Bu ayrım önemlidir: Bir uygulama bir türü veya scheme'i işleyebilecek şekilde **registered** olabilir, ancak **current default** yine de başka bir bundle ID olabilir.

## File Extension & URL scheme app handlers

Aşağıdaki satır, uzantıya bağlı olarak dosyaları açabilen uygulamaları bulmak için yararlı olabilir:
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
Buradan **URL scheme** handler'larını dump etmek için:
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
Bir örnek dosyanın UTI ağacını çözümlemek için:
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
## İlgi Çekici Info.plist Anahtarları

Bir uygulama bundle'ını triage ederken en çok önem taşıyan anahtarlar şunlardır:

- **`CFBundleDocumentTypes`**: bundle'ın açabileceğini belirttiği belge grupları.
- **`LSItemContentTypes`**: belge türlerini UTI'lere bağlamanın **modern / tercih edilen** yöntemi.
- **`LSHandlerRank`**: LaunchServices tarafından kullanılan sıralama (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: uygulama tarafından uygulanan özel URI scheme'leri.
- **`UTExportedTypeDeclarations`**: uygulamanın **sahip olduğu** UTI'ler.
- **`UTImportedTypeDeclarations`**: uygulamanın sahibi olmadığı ancak sistemin tanımasını istediği UTI'ler.

Hızlı bir triage için kullanılabilecek komut şudur:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
İnce ancak önemli bir ayrıntı: **`LSItemContentTypes`** mevcutsa **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** ve **`CFBundleTypeOSTypes`** gibi eski anahtarlar, fiilen legacy uyumluluk verileridir. Gerçek handler çözümlemesi için öncelikle UTI yoluna odaklanın.

## Offensive notes

İlginç hâle gelmeleri için uygulamaların çalıştırılması gerekmez. Yazılan veya klonlanan bir `.app` bundle’ı, **diske yazılır yazılmaz `lsd` tarafından otomatik olarak parse edilebilir** ve bildirilen document type’lar / URL scheme’ler, kullanıcı bundle’ı hiç başlatmadan register edilebilir.

Bu durum hem **persistence / hijacking research** hem de **initial-access chains** için kullanışlıdır:

- Kötü amaçlı bir uygulama **nadir bir extension** veya **custom UTI** talep edebilir ve kurbanın lure file’ı açmasını bekleyebilir.
- Kötü amaçlı bir uygulama; bir browser, Electron app, office document, chat client veya başka bir helper app üzerinden erişilebilen **custom URL scheme** register edebilir.<sup>[[1]](#references)</sup>
- Bir app bundle’ını build ettikten sonra düzenlerseniz LaunchServices’ı şu komutla bundle’ı yeniden parse etmeye zorlayabilirsiniz:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Şüpheli bundle'ları test ederken özellikle şunlara dikkat edin:

- Yaygın olmayan türlerde **`LSHandlerRank=Owner`**.
- Çok sayıda uzantıyı desteklediğini belirten geniş **`CFBundleDocumentTypes`** dizileri.
- Tek ilginç davranışı bir belge veya URI handler'ının arkasında bulunan **helper / wrapper** uygulamaları.
- LaunchServices'a yönlendirme yapan **kısayol benzeri dosyalar** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` tarzı teknikler ve ilgili Gatekeeper açıları için [bu diğer sayfaya](macos-security-protections/macos-fs-tricks/README.md) bakın.<sup>[[2]](#references)</sup>

Amacınız yalnızca bir klasöre göz atarak veya bir dosya seçerek pasif code-execution elde etmekse, farklı ancak yakından ilişkili bu dosya-handler yüzeyi için [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) özel sayfasına da bakın.

## Referanslar

- [1] [Objective-See - Custom URL Schemes Üzerinden Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate'i Atlatmak: macOS'taki Gatekeeper kusurlarına daha yakından bakış](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}

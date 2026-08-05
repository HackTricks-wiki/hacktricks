# macOS Dosya Uzantısı ve URL scheme uygulama işleyicileri

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Bu, macOS'ta yüklü olan tüm uygulamaların bulunduğu ve her yüklü uygulama hakkında desteklenen **URL schemes**, **document types**, **UTIs** ve varsayılan işleyiciler gibi bilgileri almak için sorgulanabilen bir veritabanıdır.

Bu veritabanını şu komutla dump etmek mümkündür:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ya da [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) aracını kullanarak.

**`/usr/libexec/lsd`**, veritabanının beynidir. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` ve daha fazlası gibi **birkaç XPC servisi** sağlar. Ancak açığa çıkarılan XPC işlevlerini kullanabilmeleri için uygulamalara bazı **entitlements** da atanmasını gerektirir; örneğin MIME type'lar veya URL scheme'leri için varsayılan uygulamaları değiştirmek üzere `.launchservices.changedefaulthandler` veya `.launchservices.changeurlschemehandler` ve diğerleri.

**`/System/Library/CoreServices/launchservicesd`**, `com.apple.coreservices.launchservicesd` servisini sahiplenir ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı **`/usr/bin/lsappinfo`** veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ile sorgulanabilir.

Bir operator açısından genellikle **iki kullanışlı görünüm** olduğunu unutmayın:

- LaunchServices / `lsd` tarafından yönetilen **registration database** (`.csstore` dosyalarıyla desteklenir).
- `LSHandlers` array'i içinde `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` konumunda saklanan **kullanıcı başına etkin varsayılanlar**.

Bu ayrım önemlidir: bir uygulama bir type veya scheme'i işleyebilecek şekilde **registered** olabilir, ancak **mevcut varsayılan** yine de başka bir bundle ID olabilir.

## Dosya Uzantısı ve URL scheme uygulama handler'ları

Aşağıdaki satır, uzantıya bağlı olarak dosyaları açabilen uygulamaları bulmak için yararlı olabilir:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump | grep -E "path:|bindings:|name:"
```
Ya da [**SwiftDefaultApps**](https://github.com/Lord-Kamina/SwiftDefaultApps) gibi bir şey kullanın:
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
Bundan **URL scheme** handler'larını dump etmek için:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** işleyicilerini dökmek için:
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

Bir uygulama bundle'ını incelerken aşağıdaki anahtarlar en önemlileridir:

- **`CFBundleDocumentTypes`**: bundle'ın açabileceğini belirttiği belge grupları.
- **`LSItemContentTypes`**: belge türlerini UTI'lara bağlamanın **modern / tercih edilen** yolu.
- **`LSHandlerRank`**: LaunchServices tarafından kullanılan sıralama (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: uygulama tarafından uygulanan özel URI scheme'leri.
- **`UTExportedTypeDeclarations`**: uygulamanın **sahip olduğu** UTI'lar.
- **`UTImportedTypeDeclarations`**: uygulamanın sahibi olmadığı ancak sistemin tanımasını istediği UTI'lar.

Hızlı bir triage için kullanışlı bir komut:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
İnce ancak önemli bir ayrıntı: **`LSItemContentTypes`** mevcutsa, **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** ve **`CFBundleTypeOSTypes`** gibi eski anahtarlar fiilen legacy uyumluluk verileridir. Gerçek handler çözümlemesi için öncelikle UTI yoluna odaklanın.

## Offensive notes

İlgi çekici hale gelmeleri için uygulamaların çalıştırılması gerekmez. Sisteme bırakılan veya clone edilen bir `.app` bundle'ı, **diske yazılır yazılmaz `lsd` tarafından otomatik olarak parse edilebilir** ve tanımladığı document types / URL schemes, kullanıcı bundle'ı hiç başlatmadan register edilebilir.

Bu hem **persistence / hijacking research** hem de **initial-access chains** için kullanışlıdır:

- Malicious bir app, **nadir bir extension** veya **custom UTI** talep edebilir ve kurbanın lure file'ı açmasını bekleyebilir.
- Malicious bir app; browser, Electron app, office document, chat client veya başka bir helper app üzerinden erişilebilen bir **custom URL scheme** register edebilir.<sup>[1]</sup>
- Bir app bundle'ını build ettikten sonra düzenlerseniz, LaunchServices'ın bundle'ı şu komutla yeniden parse etmesini sağlayabilirsiniz:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Şüpheli bundle'ları test ederken özellikle şunlara dikkat edin:

- Yaygın olmayan türlerde **`LSHandlerRank=Owner`**.
- Birçok extension talep eden geniş **`CFBundleDocumentTypes`** dizileri.
- İlginç davranışlarının yalnızca bir document veya URI handler arkasında bulunduğu **helper / wrapper apps**.
- Sonunda LaunchServices'a dispatch yapan **shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc`-style tricks ve ilgili Gatekeeper açıları için [bu diğer sayfaya](macos-security-protections/macos-fs-tricks/README.md) bakın.<sup>[2]</sup>

Amacınız yalnızca bir klasöre göz atarak veya bir dosya seçerek passive code-execution elde etmekse, bunun farklı ancak yakından ilişkili bir file-handler surface olması nedeniyle [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) için ayrılmış sayfaya da bakın.

## References

- [1] [Objective-See - Custom URL Schemes Üzerinden Remote Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate'i Bypass Etmek: macOS'taki Gatekeeper Flaw'larına Daha Yakından Bakış](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}

# macOS Dosya Uzantısı ve URL scheme uygulama işleyicileri

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Bu, macOS'te yüklü olan tüm uygulamaların bulunduğu ve her yüklü uygulama hakkında desteklenen **URL schemes**, **document types**, **UTIs** ve varsayılan işleyiciler gibi bilgileri almak için sorgulanabilen bir database'dir.

Bu database şu komutla dump edilebilir:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) aracını kullanarak.

**`/usr/libexec/lsd`**, veritabanının beynidir. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` ve daha fazlası gibi **birkaç XPC servisi** sağlar. Ancak açığa çıkarılan XPC işlevlerini kullanabilmeleri için uygulamalara bazı **entitlements** verilmesini de **gerektirir**. Örneğin MIME türleri veya URL scheme'leri için varsayılan uygulamaları değiştirmek üzere `.launchservices.changedefaulthandler` veya `.launchservices.changeurlschemehandler` ve diğerleri gerekir.

**`/System/Library/CoreServices/launchservicesd`**, `com.apple.coreservices.launchservicesd` servisini sahiplenir ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı **`/usr/bin/lsappinfo`** veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ile sorgulanabilir.

Bir operator perspektifinden, genellikle **iki kullanışlı görünüm** olduğunu unutmayın:

- LaunchServices / `lsd` tarafından yönetilen **registration database** (`.csstore` dosyalarıyla desteklenir).
- `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` içindeki `LSHandlers` array'inde depolanan **kullanıcı başına etkin varsayılanlar**.

Bu ayrım önemlidir: bir uygulama bir türü veya scheme'i işleyebilir olarak **registered** olabilir, ancak **mevcut varsayılan** yine de başka bir bundle ID olabilir.

## File Extension & URL scheme app handlers

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
Bir uygulamanın desteklediği dosya uzantılarını şu şekilde de kontrol edebilirsiniz:
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
Buradan **URL scheme** işleyicilerini dump etmek için:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** işleyicilerini dump etmek için:
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
## İlginç Info.plist anahtarları

Bir uygulama bundle'ını triage ederken şu anahtarlar en çok önem taşır:

- **`CFBundleDocumentTypes`**: bundle'ın açabildiğini belirttiği belge grupları.
- **`LSItemContentTypes`**: belge türlerini UTI'lara bağlamanın **modern / tercih edilen** yolu.
- **`LSHandlerRank`**: LaunchServices tarafından kullanılan sıralama (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: uygulama tarafından uygulanan özel URI scheme'leri.
- **`UTExportedTypeDeclarations`**: uygulamanın **sahip olduğu** UTI'lar.
- **`UTImportedTypeDeclarations`**: uygulamanın sahibi olmadığı ancak sistemin tanımasını istediği UTI'lar.

Hızlı bir triage için kullanılabilecek komut:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
İnce fakat önemli bir ayrıntı: **`LSItemContentTypes`** mevcutsa **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** ve **`CFBundleTypeOSTypes`** gibi eski anahtarlar fiilen legacy compatibility data niteliğindedir. Gerçek handler resolution için öncelikle UTI path'e odaklanın.

## Offensive notes

İlgi çekici hâle gelmeleri için uygulamaların çalıştırılması gerekmez. Sisteme bırakılan veya clone'lanan bir `.app` bundle, diske yazılır yazılmaz **`lsd` tarafından otomatik olarak parse edilebilir** ve tanımladığı document types / URL schemes, kullanıcı bundle'ı hiç başlatmadan register edilebilir.

Bu durum hem **persistence / hijacking research** hem de **initial-access chains** için faydalıdır:

- Malicious bir app, **rare extension** veya **custom UTI** üzerinde hak iddia edip victim'ın lure file'ı açmasını bekleyebilir.
- Malicious bir app, browser, Electron app, office document, chat client veya başka bir helper app üzerinden erişilebilen bir **custom URL scheme** register edebilir.<sup>[[1]](#references)</sup>
- Bir app bundle'ı build ettikten sonra düzenlerseniz, LaunchServices'ın bundle'ı yeniden parse etmesini şu şekilde zorlayabilirsiniz:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Şüpheli bundle'ları test ederken özellikle şunlara dikkat edin:

- Yaygın olmayan türlerde **`LSHandlerRank=Owner`**.
- Birçok uzantıyı sahiplenen geniş **`CFBundleDocumentTypes`** dizileri.
- Tek ilgi çekici davranışı bir belge veya URI handler'ının arkasında bulunan **helper / wrapper apps**.
- Sonunda LaunchServices'a yönlendirilen **shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` tarzı hileler ve ilgili Gatekeeper açıları için [this other page](macos-security-protections/macos-fs-tricks/README.md) sayfasına bakın.<sup>[[2]](#references)</sup>

Amacınız yalnızca bir klasöre göz atarak veya bir dosya seçerek pasif code-execution elde etmekse, bunun farklı ancak yakından ilişkili bir file-handler yüzeyi olması nedeniyle [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) için ayrılmış sayfaya da bakın.

## References


- [1] [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)

{{#include ../../banners/hacktricks-training.md}}

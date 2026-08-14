# macOS Dosya Uzantısı ve URL scheme uygulama işleyicileri

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Database

Bu, macOS'ta yüklü olan tüm uygulamaların; desteklenen **URL schemes**, **document types**, **UTIs** ve varsayılan işleyiciler gibi her bir yüklü uygulama hakkında bilgi almak için sorgulanabilen bir database'dir.

Bu database'i şu şekilde dump etmek mümkündür:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) aracını kullanarak.

**`/usr/libexec/lsd`**, veritabanının beynidir. `.lsd.installation`, `.lsd.open`, `.lsd.openurl` ve daha fazlası gibi **birkaç XPC servisi** sağlar. Ancak açığa çıkarılan XPC işlevlerini kullanabilmeleri için uygulamalara bazı **entitlement'lar** da verilmesini gerektirir; örneğin MIME türleri veya URL scheme'leri için varsayılan uygulamaları değiştirmek üzere `.launchservices.changedefaulthandler` veya `.launchservices.changeurlschemehandler` ve diğerleri.

**`/System/Library/CoreServices/launchservicesd`**, `com.apple.coreservices.launchservicesd` servisini claim eder ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı **`/usr/bin/lsappinfo`** veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ile sorgulanabilir.

Bir operator perspektifinden, genellikle **iki kullanışlı görünüm** olduğunu unutmayın:

- LaunchServices / `lsd` tarafından yönetilen **registration database** (`.csstore` dosyalarıyla desteklenir).
- `LSHandlers` array'i içinde `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` konumunda depolanan **kullanıcı başına effective defaults**.

Bu ayrım önemlidir: Bir uygulama bir türü veya scheme'i işleyebilecek şekilde **registered** olabilir; ancak **current default** yine de başka bir bundle ID olabilir.

Güncel macOS sürümlerinde registration discovery `/Applications` ile sınırlı değildir: Spotlight tarafından görülebilen, erişilebilir diğer klasörlerdeki ve mount edilmiş/shared volume'lerdeki uygulamalar da registry'ye girebilir. Bu nedenle triage sırasında `lsregister -dump` çıktısındaki `path` ve volume bilgilerini koruyun ve bundle keşfedilebilir durumda kaldığı sürece bir uygulamanın unregister edilmesinin kalıcı olduğunu varsaymayın.<sup>[[4]](#references)</sup>

## File Extension & URL scheme app handlers

Aşağıdaki satır, uzantıya bağlı olarak dosyaları açabilen uygulamaları bulmak için kullanışlı olabilir:
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
Bir uygulamanın desteklediği uzantıları şu işlemi yaparak da kontrol edebilirsiniz:
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

**mevcut kullanıcının varsayılanları** için en kullanışlı dosya genellikle şudur:
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
### Dosyaya özgü `Open With` geçersiz kılmaları

Handler çözümlemesinde **dosyaya özgü** bir katman da bulunur. LaunchServices, dosyanın UTI'sine ve kullanıcının global varsayılanına geri dönmeden önce `com.apple.LaunchServices.OpenWith` extended attribute'ını kontrol eder. Finder, tek bir dosya için **Always Open With** seçildiğinde bu özniteliği oluşturur; değeri uygulama yolu, bundle identifier ve version selector içeren binary property list'tir.<sup>[[3]](#references)</sup>

Dosya adı uzantısına güvenmeden bunu inceleyip decode edin:
```bash
xattr -px com.apple.LaunchServices.OpenWith ./suspicious.doc | xxd -r -p | plutil -p -
```
Bu, `duti`, `dutix` veya `LSHandlers` zararsız bir global varsayılan bildirmesine rağmen tek bir lure beklenmedik bir uygulamayla açıldığında kullanışlıdır. Kontrollü bir laboratuvar için, tam opak değer Finder üzerinden yapılandırılmış bir dosyadan kopyalanabilir; bu değerin silinmesi normal türe dayalı çözümlemeyi geri yükler:
```bash
# Clone an existing per-file association
value="$(xattr -px com.apple.LaunchServices.OpenWith ./seed.doc | tr -d '[:space:]')"
xattr -wx com.apple.LaunchServices.OpenWith "$value" ./test.doc

# Remove the override
xattr -d com.apple.LaunchServices.OpenWith ./test.doc
```
## İlginç Info.plist anahtarları

Bir uygulama bundle'ını triage ederken şu anahtarlar en önemlisidir:

- **`CFBundleDocumentTypes`**: bundle'ın açabileceğini belirttiği belge grupları.
- **`LSItemContentTypes`**: belge türlerini UTI'lara bağlamanın **modern / tercih edilen** yolu.
- **`LSHandlerRank`**: LaunchServices tarafından kullanılan sıralama (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: uygulama tarafından uygulanan özel URI scheme'leri.
- **`UTExportedTypeDeclarations`**: uygulamanın **sahip olduğu** UTI'lar.
- **`UTImportedTypeDeclarations`**: uygulamanın sahibi olmadığı ancak sistemin tanımasını istediği UTI'lar.

Hızlı bir triage komutu şudur:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
İnce ancak önemli bir ayrıntı: **`LSItemContentTypes`** mevcutsa, **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** ve **`CFBundleTypeOSTypes`** gibi eski anahtarlar fiilen legacy compatibility data niteliğindedir. Gerçek handler çözümlemesi için öncelikle UTI path'ine odaklanın.

## Offensive notes

Uygulamaların ilgi çekici hâle gelmesi için çalıştırılmaları gerekmez. Diske bırakılan veya clone edilen bir `.app` bundle'ı, **diske yazılır yazılmaz `lsd` tarafından otomatik olarak parse edilebilir** ve tanımladığı document type'lar / URL scheme'leri, kullanıcı bundle'ı hiç başlatmadan register edilebilir.

Bu durum hem **persistence / hijacking research** hem de **initial-access chains** için kullanışlıdır:

- Malicious bir app, **nadir bir extension** veya **custom UTI** talep edebilir ve victim'ın lure file'ı açmasını bekleyebilir.
- Malicious bir app, bir browser, Electron app, office document, chat client veya başka bir helper app üzerinden erişilebilen **custom URL scheme** register edebilir.<sup>[[1]](#references)</sup>
- Normal default resolution'ı belirli bir candidate handler'ı test etmekten ayırmak için scheme'i LaunchServices üzerinden `open 'targetscheme://host/path?value=test'` ile çağırın; ardından belirli bir registered bundle'ı `open -b com.vendor.Target 'targetscheme://host/path?value=test'` ile hedefleyin. Bu, receiving app'in attacker-controlled URL component'lerini nasıl validate edip decode ettiğini audit etmek için kullanışlıdır.<sup>[[1]](#references)</sup>
- Bir app bundle'ını build ettikten sonra düzenlerseniz, LaunchServices'ın bundle'ı yeniden parse etmesini şu komutla zorlayabilirsiniz:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Şüpheli bundle'ları test ederken özellikle şunlara dikkat edin:

- Yaygın olmayan türlerde **`LSHandlerRank=Owner`**.
- Birçok extension talep eden geniş **`CFBundleDocumentTypes`** dizileri.
- Tek ilgi çekici davranışı bir document veya URI handler'ın arkasında olan **Helper / wrapper apps**.
- LaunchServices'e yönlendiren **kısayol benzeri dosyalar** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc` tarzı trick'ler ve ilgili Gatekeeper açıları için [bu diğer sayfaya](macos-security-protections/macos-fs-tricks/README.md) bakın.<sup>[[2]](#references)</sup>

Amacınız yalnızca bir klasöre göz atarak veya bir dosya seçerek pasif **code-execution** elde etmekse, [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) için ayrılmış sayfaya da bakın; bu, farklı ancak yakından ilişkili bir file-handler yüzeyidir.



## References

- [1] [Objective-See - Özel URL Schemes Üzerinden Uzaktan Mac Exploitation](https://objective-see.org/blog/blog_0x38.html)
- [2] [Jamf Threat Labs - Gate'i Aşmak: macOS'taki Gatekeeper Açıklarına Daha Yakından Bakış](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
- [3] [The Eclectic Light Company - macOS Bir Dosyayı Doğru Uygulamada Nasıl Açar](https://eclecticlight.co/2024/04/10/how-macos-opens-a-file-in-the-correct-app/)
- [4] [The Eclectic Light Company - macOS Sequoia'da LaunchServices'i Kontrol Etme](https://eclecticlight.co/2025/03/27/controlling-launchservices-in-macos-sequoia/)
{{#include ../../banners/hacktricks-training.md}}

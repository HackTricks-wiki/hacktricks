# macOS Dosya Uzantısı & URL scheme uygulama işleyicileri

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Veritabanı

Bu, macOS'ta kurulu tüm uygulamaların bir veritabanıdır; her kurulu uygulama hakkında desteklenen **URL schemes**, **document types**, **UTIs** ve varsayılan işleyiciler gibi bilgileri almak için sorgulanabilir.

Bu veritabanını şu şekilde dump etmek mümkündür:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Ya da [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) aracını kullanarak.

**`/usr/libexec/lsd`** veritabanının beynidir. **`.lsd.installation`, `.lsd.open`, `.lsd.openurl`** ve daha fazlası gibi **birkaç XPC servisi** sağlar. Ancak ayrıca uygulamaların açığa sunulan XPC işlevlerini kullanabilmesi için bazı **entitlements** da gerektirir; örneğin MIME türleri veya URL şemaları için varsayılan uygulamaları değiştirmek üzere `.launchservices.changedefaulthandler` ya da `.launchservices.changeurlschemehandler` ve diğerleri.

**`/System/Library/CoreServices/launchservicesd`** `com.apple.coreservices.launchservicesd` servisini sahiplenir ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı **`/usr/bin/lsappinfo`** ile veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ile sorgulanabilir.

Operatör perspektifinden, genellikle **iki faydalı görünüm** olduğunu unutmayın:

- LaunchServices / `lsd` tarafından yönetilen **registration database** (`.csstore` dosyaları tarafından desteklenir).
- `~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist` içinde, `LSHandlers` dizisinde saklanan **kullanıcı bazlı etkin varsayılanlar**.

Bu ayrım önemlidir: Bir uygulama, bir türü veya şemayı işleyebilecek şekilde **registered** olabilir, ancak **mevcut varsayılan** yine de başka bir bundle ID olabilir.

## File Extension & URL scheme app handlers

Aşağıdaki satır, uzantıya göre dosyaları açabilen uygulamaları bulmak için faydalı olabilir:
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
Bir uygulamanın desteklediği uzantıları ayrıca şu şekilde kontrol edebilirsiniz:
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
## Etkin handler'ları numaralandırma

**Mevcut kullanıcının defaults** için en faydalı dosya genellikle şudur:
```bash
~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist
```
Ondan **URL scheme** handler'larını dökmek için:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerURLScheme != null) |
{scheme: .LSHandlerURLScheme, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
**content-type / UTI** handler’larını dökmek için:
```bash
plutil -extract LSHandlers json -o - ~/Library/Preferences/com.apple.LaunchServices/com.apple.launchservices.secure.plist |
jq '.[] | select(.LSHandlerContentType != null) |
{uti: .LSHandlerContentType, handler: (.LSHandlerRoleAll // .LSHandlerRoleViewer // .LSHandlerRoleEditor)}'
```
Bir örnek dosyanın UTI ağacını çözümlemek için:
```bash
mdls -name kMDItemContentType -name kMDItemContentTypeTree ./sample.pdf
```
Eğer varsayılanları sorgulamak veya değiştirmek için daha kullanıcı dostu bir CLI istiyorsanız:
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

Bir application bundle’ı triage ederken, bu anahtarlar en önemlileridir:

- **`CFBundleDocumentTypes`**: bundle’ın açabileceğini iddia ettiği document grupları.
- **`LSItemContentTypes`**: document türlerini UTIs’e bağlamak için **modern / preferred** yol.
- **`LSHandlerRank`**: LaunchServices tarafından kullanılan sıralama (`Owner`, `Default`, `Alternate`, `None`).
- **`CFBundleURLTypes`** / **`CFBundleURLSchemes`**: app tarafından implemente edilen custom URI schemes.
- **`UTExportedTypeDeclarations`**: app’in **sahip olduğu** UTIs.
- **`UTImportedTypeDeclarations`**: app’in sahip olmadığı ama sistemin tanımasını istediği UTIs.

Kullanışlı bir hızlı triage komutu:
```bash
plutil -p /Applications/Target.app/Contents/Info.plist | \
rg 'CFBundleDocumentTypes|CFBundleURLTypes|LSItemContentTypes|LSHandlerRank|UTExportedTypeDeclarations|UTImportedTypeDeclarations'
```
İnce ama önemli bir ayrıntı: eğer **`LSItemContentTypes`** mevcutsa, **`CFBundleTypeExtensions`**, **`CFBundleTypeMIMETypes`** ve **`CFBundleTypeOSTypes`** gibi daha eski anahtarlar fiilen legacy uyumluluk verisidir. Gerçek handler resolution için önce UTI yoluna odaklanın.

## Offensive notes

Applications çalıştırılmadan da ilgi çekici hale gelebilir. Bırakılmış veya klonlanmış bir `.app` bundle, diske yazılır yazılmaz **`lsd` tarafından otomatik olarak parse edilebilir**, ve tanımladığı document types / URL schemes, kullanıcı bundle’ı hiç açmadan kaydedilebilir.

Bu, hem **persistence / hijacking research** hem de **initial-access chains** için faydalıdır:

- Kötü amaçlı bir app, **nadir bir extension** ya da **custom UTI** iddia edebilir ve kurbanın lure file’ı açmasını bekleyebilir.
- Kötü amaçlı bir app, browser, Electron app, office document, chat client veya başka bir helper app’ten erişilebilen **custom URL scheme** kaydedebilir.
- Bir app bundle’ını build ettikten sonra düzenlerseniz, LaunchServices’i onu yeniden parse etmeye zorlayabilirsiniz:
```bash
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -f /tmp/Evil.app
```
Şüpheli bundles test ederken, şunlara özellikle dikkat edin:

- Alışılmadık türlerde **`LSHandlerRank=Owner`**.
- Birçok extension iddia eden geniş **`CFBundleDocumentTypes`** array’leri.
- Tek ilginç davranışı document veya URI handler arkasında olan **helper / wrapper apps**.
- Sonunda LaunchServices içine dispatch eden **shortcut-like files** (`.webloc`, `.inetloc`, `.fileloc`). `.fileloc`-style tricks ve ilgili Gatekeeper açıları için [bu diğer sayfaya](macos-security-protections/macos-fs-tricks/README.md) bakın.

Amacınız sadece bir klasöre göz atarak veya bir dosya seçerek pasif code-execution elde etmekse, ayrıca [Quick Look generators](macos-proces-abuse/macos-quicklook-generators.md) için ayrılmış sayfayı da kontrol edin; çünkü bu farklı ama yakından ilişkili bir file-handler surface’tir.

## References

- [Objective-See - Remote Mac Exploitation Via Custom URL Schemes](https://objective-see.org/blog/blog_0x38.html)
- [Jamf Threat Labs - Bypassing the Gate: A closer look into Gatekeeper flaws on macOS](https://www.jamf.com/blog/gatekeeper-flaws-on-macos/)
{{#include ../../banners/hacktricks-training.md}}

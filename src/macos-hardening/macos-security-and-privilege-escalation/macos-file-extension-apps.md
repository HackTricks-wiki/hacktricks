# macOS Dosya Uzantısı & URL şeması uygulama işleyicileri

{{#include ../../banners/hacktricks-training.md}}

## LaunchServices Veritabanı

Bu, macOS'ta yüklü olan tüm uygulamaların bir veritabanıdır ve her yüklü uygulama hakkında desteklediği URL şemaları ve MIME türleri gibi bilgileri almak için sorgulanabilir.

Bu veritabanını dökmek mümkündür:
```
/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsregister -dump
```
Veya aracı [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) kullanarak.

**`/usr/libexec/lsd`** veritabanının beyinidir. **.lsd.installation**, **.lsd.open**, **.lsd.openurl** gibi **birçok XPC hizmeti** sağlar. Ancak, aynı zamanda **açık XPC işlevselliklerini** kullanabilmek için uygulamalara bazı yetkilendirmeler de gerektirir; örneğin, mime türleri veya url şemaları için varsayılan uygulamaları değiştirmek üzere **.launchservices.changedefaulthandler** veya **.launchservices.changeurlschemehandler** gibi.

**`/System/Library/CoreServices/launchservicesd`** `com.apple.coreservices.launchservicesd` hizmetini talep eder ve çalışan uygulamalar hakkında bilgi almak için sorgulanabilir. Sistem aracı /**`usr/bin/lsappinfo`** ile veya [**lsdtrip**](https://newosxbook.com/tools/lsdtrip.html) ile sorgulanabilir.

## Dosya Uzantısı & URL şeması uygulama işleyicileri

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
Bir uygulamanın desteklediği uzantıları kontrol etmek için:
```
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
{{#include ../../banners/hacktricks-training.md}}

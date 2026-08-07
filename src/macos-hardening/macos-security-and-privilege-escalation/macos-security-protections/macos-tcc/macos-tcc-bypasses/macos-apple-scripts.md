# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Görev otomasyonu için **remote processes ile etkileşim kuran** bir scripting language'dir. Diğer process'lerden **bazı işlemleri gerçekleştirmelerini istemeyi** oldukça kolaylaştırır. **Malware**, diğer process'ler tarafından export edilen function'ları abuse etmek için bu özellikleri kötüye kullanabilir.\
Örneğin bir malware, **browser'da açılmış sayfalara arbitrary JS code inject edebilir**. Veya kullanıcıdan istenen bazı allow permission'larını **auto click** ile onaylayabilir;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
İşte bazı örnekler: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
applescripts kullanan malware hakkında daha fazla bilgiyi [**burada**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/).<sup>[[3]](#references)</sup>

### Automation / TCC tuhaflıkları

Apple Events onayları **yönlüdür**: istem, bir **kaynak işlem -> hedef işlem** çifti içindir. Kullanıcı **Allow** düğmesine tıkladığında, aynı kaynaktan aynı hedefe yapılan sonraki istekler, giriş sıfırlanana kadar izinli olur. Test sırasında `Terminal -> Finder` veya `Terminal -> System Events` izninin bir kez verilmesi, daha sonra başka bir açılır pencere gösterilmeden bu iznin yeniden kullanılmasına yeterlidir.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Bu, **target** **Finder** olduğunda özellikle önemlidir; çünkü Finder, FDA UI'da görünmese bile her zaman **Full Disk Access** yetkisine sahiptir. Bu nedenle, Finder üzerinde zaten Automation yetkisi bulunan herhangi bir host, TCC tarafından korunan dosyalara erişmek için AppleScript/JXA proxy'si olarak kullanılabilir.<sup>[[1]](#references)</sup> Generic Finder ve System Events payload'ları zaten [ana TCC sayfasında](../README.md) ve [Apple Events sayfasında](../macos-apple-events.md) belgelenmiştir.

### Modern offensive tradecraft

`/usr/bin/osascript` yalnızca en görünür giriş noktasıdır. AppleScript ve JXA, **`NSAppleScript`** / **`OSAScript`** aracılığıyla **Mach-O binaries** üzerinden de çalıştırılabilir; bu, hem evasion hem de hâlihazırda ilgi çekici TCC izinlerine sahip bir host içinde çalışmak için kullanışlıdır.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Özel bir helper oluşturup Apple Events'ı doğrudan gönderiyorsanız, ona **gerçek bir uygulama kimliği** vermek testleri ve operasyonları çok daha güvenilir hâle getirir. Uygulamada bu; `CFBundleIdentifier` ve `NSAppleEventsUsageDescription` içeren bir `Info.plist` gömmek, binary'yi imzalamak ve `com.apple.security.automation.apple-events` entitlement'ını vermek anlamına gelir. Aksi hâlde Apple Events istemi çoğunlukla **parent host**'a (örneğin `Terminal`) atfedilir veya `NSAppleScript` execution, kafa karıştırıcı `-1750` / `errOSASystemError` hatalarıyla başarısız olur.<sup>[[2]](#references)</sup>

Apple scripts kolayca "**compiled**" hâle getirilebilir. Bu sürümler `osadecompile` ile kolayca "**decompiled**" hâle getirilebilir.

Ancak bu script'ler **"Read only"** olarak da export edilebilir ("Export..." seçeneğiyle):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
ve bu durumda içerik `osadecompile` ile bile decompile edilemez

Ancak bu tür executable'ları anlamak için kullanılabilecek bazı araçlar hâlâ mevcut; [**daha fazla bilgi için bu araştırmayı okuyun**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) aracı, [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) ile birlikte script'in nasıl çalıştığını anlamak için oldukça faydalı olacaktır.

## Referanslar

- [1] [macOS TCC Kullanıcı Gizliliği Korumalarını Kazara ve Tasarım Yoluyla Atlatma](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [AppleScript'i macOS CLI Araçlarında Çalıştırmak: Belgelenmemiş Kısımlar](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actor'lar macOS'a Saldırmak İçin AppleScript'i Nasıl Kullanıyor](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Kötücül Run-Only AppleScript'leri Reverse Etme Maceraları](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}

# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Görev otomasyonu için **uzak işlemlerle etkileşime giren** bir scripting dilidir. **Diğer işlemlerden bazı eylemleri gerçekleştirmelerini istemeyi** oldukça kolaylaştırır. **Malware**, diğer işlemler tarafından dışa aktarılan işlevleri kötüye kullanmak için bu özelliklerden yararlanabilir.\
Örneğin bir Malware, browser'da açılmış sayfalara **keyfi JS code enjekte edebilir**. Ya da kullanıcıdan istenen bazı izinlerde **otomatik olarak tıklayabilir**;<sup>[3]</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
İşte bazı örnekler: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts kullanan malware hakkında daha fazla bilgiye [**buradan**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) ulaşabilirsiniz.

### Otomasyon / TCC ayrıntıları

Apple Events onayları **yönlüdür**: istem, bir **kaynak process -> hedef process** çifti içindir. Kullanıcı **Allow** seçeneğine tıkladığında, aynı kaynaktan aynı hedefe yapılan sonraki istekler, giriş sıfırlanana kadar izinli olur. Test sırasında `Terminal -> Finder` veya `Terminal -> System Events` iznini bir kez vermek, daha sonra başka bir popup görüntülenmeden bu izni yeniden kullanmak için yeterlidir.<sup>[1]</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Bu durum özellikle **target** **Finder** olduğunda önemlidir; çünkü Finder, FDA UI'da görünmese bile her zaman **Full Disk Access** yetkisine sahiptir. Bu nedenle, Finder üzerinde zaten Automation yetkisi bulunan herhangi bir host, TCC tarafından korunan dosyalara erişmek için AppleScript/JXA proxy'si olarak kullanılabilir.<sup>[1]</sup> Generic Finder ve System Events payload'ları [ana TCC sayfasında](../README.md) ve [Apple Events sayfasında](../macos-apple-events.md) zaten belgelenmiştir.

### Modern offensive tradecraft

`/usr/bin/osascript` yalnızca en görünür giriş noktasıdır. AppleScript ve JXA, hem kaçınma amacıyla hem de zaten ilgi çekici TCC grant'lerine sahip bir host içinde çalışmak için **`NSAppleScript`** / **`OSAScript`** aracılığıyla **Mach-O binaries** içinden de çalıştırılabilir.<sup>[2]</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Özel bir helper oluşturup Apple Events'ı doğrudan gönderiyorsanız, ona **gerçek bir uygulama kimliği** vermek testleri ve operasyonları çok daha güvenilir hâle getirir. Pratikte bu; `CFBundleIdentifier` ve `NSAppleEventsUsageDescription` içeren bir `Info.plist` yerleştirmek, binary'yi imzalamak ve `com.apple.security.automation.apple-events` entitlement'ını vermek anlamına gelir. Aksi takdirde Apple Events istemi çoğunlukla **üst host**'a (örneğin `Terminal`) atfedilir veya `NSAppleScript` yürütmesi kafa karıştırıcı `-1750` / `errOSASystemError` hatalarıyla başarısız olur.<sup>[2]</sup>

Apple script'ler kolayca "**derlenebilir**". Bu sürümler `osadecompile` ile kolayca "**decompile**" edilebilir.

Ancak bu script'ler **"Salt okunur"** olarak da ( "Export..." seçeneği aracılığıyla) dışa aktarılabilir:

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
ve bu durumda içerik `osadecompile` ile bile decompile edilemez

Ancak bu tür executable dosyalarını anlamak için kullanılabilecek bazı araçlar hâlâ mevcut. [**daha fazla bilgi için bu araştırmayı okuyun**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[4]</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) aracı ve [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile), scriptin nasıl çalıştığını anlamak için oldukça kullanışlı olacaktır.

## Referanslar

- [1] [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [How Offensive Actors Use AppleScript For Attacking macOS](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Adventures in Reversing Malicious Run-Only AppleScripts](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}

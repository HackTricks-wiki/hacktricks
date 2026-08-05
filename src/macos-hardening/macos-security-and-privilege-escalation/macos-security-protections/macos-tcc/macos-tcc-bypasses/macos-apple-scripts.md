# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

**remote processes** ile etkileşime girerek görev otomasyonu için kullanılan bir scripting dilidir. Diğer process'lerden bazı eylemleri gerçekleştirmelerini **istemeyi** oldukça kolaylaştırır. **Malware**, diğer process'ler tarafından export edilen işlevleri kötüye kullanmak için bu özelliklerden yararlanabilir.\
Örneğin bir malware, browser'da açılmış sayfalara **rastgele JS kodu enjekte edebilir**. Ya da kullanıcıdan istenen bazı izinleri onaylamak için **otomatik tıklama** gerçekleştirebilir;<sup>[[3]](#references)</sup>
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
İşte bazı örnekler: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
AppleScripts kullanan malware hakkında daha fazla bilgiyi [**burada**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) bulabilirsiniz.

### Automation / TCC quirks

Apple Events onayları **yönlüdür**: istem, bir **source process -> target process** çifti içindir. Kullanıcı **Allow** düğmesine tıkladığında, aynı source process'ten aynı target process'e gönderilen sonraki istekler, kayıt sıfırlanana kadar onaylanır. Test sırasında `Terminal -> Finder` veya `Terminal -> System Events` erişimine bir kez izin vermek, daha sonra başka bir popup görüntülenmeden iznin yeniden kullanılabilmesi için yeterlidir.<sup>[[1]](#references)</sup>
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Bu, özellikle **hedef** **Finder** olduğunda önemlidir; çünkü Finder, FDA UI'da görünmese bile her zaman **Full Disk Access** yetkisine sahiptir. Bu nedenle, Finder üzerinde zaten **Automation** yetkisi bulunan herhangi bir host, TCC-korumalı dosyalara erişmek için AppleScript/JXA proxy'si olarak kullanılabilir.<sup>[[1]](#references)</sup> Generic Finder ve System Events payload'ları [the main TCC page](../README.md) ve [the Apple Events page](../macos-apple-events.md) içinde zaten belgelenmiştir.

### Modern offensive tradecraft

`/usr/bin/osascript` yalnızca en görünür entry point'tir. AppleScript ve JXA, **`NSAppleScript`** / **`OSAScript`** aracılığıyla **Mach-O binaries** üzerinden de çalıştırılabilir; bu, hem evasion hem de ilgi çekici TCC izinlerine zaten sahip bir host içinde çalışmak için kullanışlıdır.<sup>[[2]](#references)</sup>
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Özel bir helper oluşturup Apple Events'ı doğrudan gönderiyorsanız, ona **gerçek bir uygulama kimliği** vermek testleri ve işlemleri çok daha güvenilir hale getirir. Pratikte bu; `CFBundleIdentifier` ve `NSAppleEventsUsageDescription` içeren bir `Info.plist` gömmek, binary'yi imzalamak ve `com.apple.security.automation.apple-events` entitlement'ını vermek anlamına gelir. Aksi takdirde Apple Events prompt'u çoğunlukla **parent host**'a (örneğin `Terminal`) atfedilir veya `NSAppleScript` çalıştırması kafa karıştırıcı `-1750` / `errOSASystemError` hatalarıyla başarısız olur.<sup>[[2]](#references)</sup>

Apple script'ler kolayca "**compiled**" edilebilir. Bu sürümler `osadecompile` ile kolayca "**decompiled**" edilebilir.

Ancak bu script'ler **"Read only"** olarak da export edilebilir ("Export..." seçeneği aracılığıyla):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
ve bu durumda içerik `osadecompile` ile bile decompile edilemez

Ancak bu tür executable'ları anlamak için kullanılabilecek bazı araçlar hâlâ mevcut; [**daha fazla bilgi için bu araştırmayı okuyun**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)).<sup>[[4]](#references)</sup> [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) aracı, [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) ile birlikte script'in nasıl çalıştığını anlamak için oldukça faydalı olacaktır.

## Referanslar

- [1] [macOS TCC User Privacy Protections'ı Yanlışlıkla ve Tasarım Yoluyla Bypass Etme](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [2] [macOS CLI Tools'ta AppleScript'i Çalıştırma: Belgelenmemiş Kısımlar](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)
- [3] [Offensive Actor'lar macOS'a Saldırmak İçin AppleScript'i Nasıl Kullanıyor](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/)
- [4] [FADE DEAD | Kötücül Run-Only AppleScript'leri Reverse Etme Maceraları](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)

{{#include ../../../../../banners/hacktricks-training.md}}

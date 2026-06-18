# macOS Apple Scripts

{{#include ../../../../../banners/hacktricks-training.md}}

## Apple Scripts

Uzak süreçlerle **etkileşerek** görev otomasyonu için kullanılan bir scripting language'dir. Diğer süreçlerden bazı eylemleri gerçekleştirmelerini **istemeyi** oldukça kolaylaştırır. **Malware**, bu özellikleri başka süreçler tarafından dışa aktarılan işlevleri kötüye kullanmak için kullanabilir.\
Örneğin, bir malware tarayıcıda açık sayfalara **keyfi JS kodu enjekte edebilir**. Ya da kullanıcıdan istenen bazı izinleri **otomatik olarak tıklayabilir**;
```applescript
tell window 1 of process "SecurityAgent"
click button "Always Allow" of group 1
end tell
```
Burada bazı örnekler var: [https://github.com/abbeycode/AppleScripts](https://github.com/abbeycode/AppleScripts)\
applescripts kullanarak malware hakkında daha fazla bilgiye [**buradan**](https://www.sentinelone.com/blog/how-offensive-actors-use-applescript-for-attacking-macos/) ulaşın.

### Automation / TCC quirks

Apple Events onayları **directional**dır: prompt, bir **source process -> target process** çifti içindir. User **Allow**’a tıkladıktan sonra, aynı source’tan aynı target’a yapılan future requests, entry resetlenene kadar allowed olur. Testing sırasında, `Terminal -> Finder` veya `Terminal -> System Events` için bir kez izin vermek, daha sonra başka bir popup olmadan permission’ı yeniden kullanmak için yeterlidir.
```bash
# Remove previously granted Automation permissions from Terminal
tccutil reset AppleEvents com.apple.Terminal
```
Bu, özellikle **hedef** **Finder** olduğunda önemlidir; çünkü Finder, FDA UI’da görünmese bile her zaman **Full Disk Access**’e sahiptir. Bu nedenle, Finder üzerinde Automation’a zaten sahip olan herhangi bir host, TCC ile korunan dosyalara erişmek için bir AppleScript/JXA proxy’si olarak kullanılabilir. Genel Finder ve System Events payload’ları zaten [ana TCC sayfasında](../README.md) ve [Apple Events sayfasında](../macos-apple-events.md) belgelenmiştir.

### Modern offensive tradecraft

`/usr/bin/osascript` yalnızca en görünür giriş noktasıdır. AppleScript ve JXA ayrıca **Mach-O binaries** üzerinden **`NSAppleScript`** / **`OSAScript`** aracılığıyla da çalıştırılabilir; bu, hem evasion hem de zaten ilginç TCC grants’e sahip bir host içinde çalışmak için kullanışlıdır.
```bash
osascript -l JavaScript <<'EOF'
const app = Application.currentApplication();
app.includeStandardAdditions = true;
app.doShellScript("id > /tmp/jxa_id");
EOF
```
Özel bir yardımcı araç oluşturup doğrudan Apple Events gönderiyorsanız, ona **gerçek bir app identity** vermek testleri ve operasyonları çok daha güvenilir hale getirir. Pratikte bu, `Info.plist` içine `CFBundleIdentifier` ve `NSAppleEventsUsageDescription` eklemeyi, binary’yi sign etmeyi ve `com.apple.security.automation.apple-events` entitlement’ını vermeyi ifade eder. Aksi halde Apple Events prompt’u sık sık **parent host**’a (örneğin `Terminal`) atfedilir ya da `NSAppleScript` çalıştırması kafa karıştırıcı `-1750` / `errOSASystemError` hatalarıyla başarısız olur.

Apple script’ler kolayca "**compiled**" edilebilir. Bu sürümler `osadecompile` ile kolayca "**decompiled**" edilebilir

Ancak, bu script’ler ayrıca "**Read only**" olarak da export edilebilir ("Export..." seçeneği üzerinden):

<figure><img src="https://github.com/carlospolop/hacktricks/raw/master/images/image%20(556).png" alt=""><figcaption></figcaption></figure>
```
file mal.scpt
mal.scpt: AppleScript compiled
```
ve bu durumda içerik `osadecompile` ile bile decompile edilemez

Ancak, bu tür executable'ları anlamak için yine de kullanılabilecek bazı tools vardır, [**daha fazla bilgi için bu research'ü okuyun**](https://labs.sentinelone.com/fade-dead-adventures-in-reversing-malicious-run-only-applescripts/)). [**applescript-disassembler**](https://github.com/Jinmo/applescript-disassembler) ile [**aevt_decompile**](https://github.com/SentineLabs/aevt_decompile) tool'u, script'in nasıl çalıştığını anlamak için çok faydalı olacaktır.

## References

- [Bypassing macOS TCC User Privacy Protections by Accident and Design](https://www.sentinelone.com/labs/bypassing-macos-tcc-user-privacy-protections-by-accident-and-design/)
- [Making AppleScript Work in macOS CLI Tools: The Undocumented Parts](https://steipete.me/posts/2025/applescript-cli-macos-complete-guide)

{{#include ../../../../../banners/hacktricks-training.md}}

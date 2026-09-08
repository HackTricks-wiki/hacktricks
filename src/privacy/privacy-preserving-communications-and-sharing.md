# Privacy-Preserving Communications and Sharing

Uçtan uca şifreleme içeriği korur. Ancak account, phone number, contact graph, IP address, push token, notification preview, timing, file metadata veya recipient behavior bilgilerini otomatik olarak gizlemez. Bir aracı, kaldırdığı metadata ve dahil ettiği gözlemciler üzerinden seçin.

## İletişim modellerini karşılaştırın

| Araç/model | Yararlı özellik | Kalan gözlemciler ve sınırlamalar |
|---|---|---|
| Signal | Olgun E2EE; usernames, number paylaşmadan contact başlatabilir; sealed sender, service metadata miktarını azaltır | Registration için phone number gerekir; service, push provider, contacts ve endpoints bazı gözlemleri saklar |
| SimpleX | Global user identifier yoktur; contact başına queues; isteğe bağlı Tor transport | Relay timing/transport, push service, invitations ve endpoints; daha yeni/küçük ecosystem |
| Briar | Direct synchronization; online durumunda Tor; offline durumda Bluetooth/Wi-Fi; central message store yoktur | Contacts ve endpoints; local radio observers; Android odaklıdır; her iki taraf da hazır olmalı veya Mailbox kullanılmalıdır |
| OnionShare | Temporary onion service üzerinden direct file/receive/chat/site; storage provider yoktur | Sender computer service olarak çalışır; link bearer erişimi öğrenir; timing ve endpoints kalır |
| `age` encrypted file | Transport'tan bağımsız basit recipient-key encryption | Transport sender/recipient/timing/size bilgilerini görür; filenames/archive metadata ve endpoints kalır |
| Ordinary email + TLS | Server-to-server channel encryption | Her iki mail provider da normalde içeriği okuyabilir ve routing/account metadata bilgilerini saklayabilir |

## Signal: number disclosure olmadan private contact

Signal usernames, kullanıcının phone number bilgisini yeni contact'a açıklamadan chat başlatabilir; ancak registration için phone number hâlâ gereklidir.<sup>[[1]](#references)</sup> Sealed sender, kademeli bir metadata korumasıdır; tüm IP/timing correlation yöntemlerine karşı direnç sağlamaz.<sup>[[2]](#references)</sup>

### İş akışı

1. Signal'ı official app store/project üzerinden yükleyin ve önce OS'yi update edin.
2. Yasal olarak kullanma hakkınız olan bir number ile register olun. Rented SMS activations, başka birinin number bilgisini veya false identity ile edinilmiş bir provider account kullanmayın.
3. **Settings → Privacy → Phone Number** bölümünde, threat model'e göre number bilgisini kimlerin görebileceğini ve account'u number üzerinden kimlerin bulabileceğini ayarlayın.
4. New-contact discovery için bir username oluşturun. Exact link/QR bilgisini zaten authenticated bir channel üzerinden paylaşın; usernames değişebilir ve profile name değildir.
5. Kolaylık linkage riskine değmiyorsa contact upload/permissions özelliklerini disable edin ve platform destekliyorsa contacts bilgilerini manuel ekleyin.
6. Sensitive content göndermeden önce contact details'ı açın ve safety number/QR bilgisini ikinci bir channel üzerinden veya yüz yüze karşılaştırın.
7. Linked devices, registration lock/PIN, notification previews, screen security, call relaying, disappearing-message defaults ve backup behavior ayarlarını gözden geçirin.
8. Hassas olmayan bir test message gönderin ve call yapın. Her iki tarafta lock-screen, desktop, wearable ve cloud-notification izlerini inceleyin.
9. Değişen bir safety number veya beklenmeyen linked device durumunu otomatik olarak kapatılacak bir alert değil, investigation event olarak ele alın.

Pseudonymous bir profile photo, bio, group membership veya schedule bilgisini identifying bir Signal context ile birleştirmeyin.

## SimpleX: global identifier olmadan contact başına connections

SimpleX, messages bilgisini unidirectional queues üzerinden yönlendirir ve network-wide bir user identifier atamaz. Kendi policy dokümanı yine de transport sessions, temporary server data, push-notification tradeoffs ve endpoint responsibility konularını açıklar.<sup>[[3]](#references)</sup>

### İş akışı

1. Maintained bir client'ı official project/store üzerinden indirin ve publisher'ı doğrulayın. Identities birbirine karışmamalıysa dedicated bir OS/app profile kullanın.
2. Context'e özel bir display name ve image içeren **local** bir profile oluşturun. Backup olmadan app'i silmek profile ve connections bilgilerinin kaybolmasına neden olabilir.
3. İlk çalıştırmada notification mode seçimini bilinçli yapın. Instant mobile push, Apple/Google infrastructure'ına ek metadata açıklayabilir.
4. Tek bir contact için one-time invitation link oluşturun. Bunu authenticated bir channel üzerinden aktarın; live invitation elde eden herkes bunu kullanmayı deneyebilir.
5. Bağlandıktan sonra contact details'ı açın ve security code bilgisini yüz yüze veya bağımsız, doğrulanmış bir channel üzerinden karşılaştırın.<sup>[[4]](#references)</sup>
6. Desteklendiği yerlerde aynı profile'ı ilgisiz gruplar arasında yeniden kullanmak yerine incognito per-group profile kullanın.
7. Local network/server direct IP bilgisini görmemeliyse client'ın desteklediği Tor transport'ı configure edin. Değişiklikten sonra connection'ı doğrulayın; desteklenmeyen bir system proxy'yi zorlamayın.
8. Delivery receipts, link previews, calls, automatic downloads ve database export/backup ayarlarını gözden geçirin. Her biri metadata veya endpoint exposure durumunu değiştirir.
9. Duplicated live profile state çalıştırmadan, yedek ve izole bir device üzerinde recovery'yi test edin; project, eşzamanlı kopyaların conversations akışını bozabileceği konusunda uyarır.

Global identifier olmaması, bir contact'ın user'ı content, profile reuse, invitation delivery, timing veya social graph üzerinden tanımlamasını engellemez.

## Briar: direct ve disruption-resistant messaging

Briar, devices arasında doğrudan synchronization yapar; online durumunda Tor, local outages sırasında ise Bluetooth/Wi-Fi kullanır. Official threat model, short-range radio üzerindeki adversarial monitoring faaliyetlerinin yalnızca sınırlı olduğunu varsayar; bu nedenle local wireless görünmez değildir.<sup>[[5]](#references)</sup>

### İş akışı

1. Official Briar distribution üzerinden install edin ve package source'u doğrulayın. Güncel security updates içeren supported bir Android device kullanın.
2. Unique bir context nickname ve güçlü bir password ile local account oluşturun. Password-reset path yoktur; unlock secret bilgisinin recoverable olduğunu test edin.
3. Mümkün olduğunda contacts'ı birbirinizin QR code'unu scan ederek face-to-face ekleyin. Bu, contact'ı authenticate eder ve link'in correlatable bir channel üzerinden gönderilmesini önler.
4. Connectivity settings içinde yalnızca gerekli transports özelliklerini enable edin: Tor/Internet, Wi-Fi ve/veya Bluetooth. Gerekmediğinde local radios özelliklerini disable edin.
5. Asynchronous delivery için dedicated ve sürekli güç alan bir device üzerinde Briar Mailbox kullanmayı değerlendirin; bunu bir message server gibi inventory'ye alın ve fiziksel olarak koruyun.
6. Internet kullanılabilir durumdayken benign bir test gönderin, ardından Internet'i owner-authorized bir location içinde disable ederek planlanan outage path'i test edin.
7. Android backups, notification previews, screenshots ve exported content bilgilerini inceleyin. Local encrypted storage, endpoint unlock/compromise olduğunda açığa çıkar.
8. Kayıp contacts/devices bilgilerini kaldırın ve physical custody veya account password compromise olduysa tüm context'i retire edin.

## OnionShare: direct temporary transfer

OnionShare, sender/receiver computer üzerinde bir onion service çalıştırır; files bir storage provider'a upload edilmez ve traffic, Tor içinde uçtan uca şifrelenir.<sup>[[6]](#references)</sup> Complete onion URL bir bearer capability'dir ve korunmalıdır.

### GUI file-sharing workflow

1. OnionShare'ı official signed distribution üzerinden ve recipient tarafına Tor Browser'ı install edin.
2. Files bilgilerinin **sanitized copies** kopyalarını dedicated bir staging directory içine koyun. OnionShare'ı personal home directory'ye yönlendirmeyin.
3. **Share Files** seçeneğini açın, yalnızca staged files'ı ekleyin, private key/access protection özelliğini etkin bırakın ve bir recipient için **Stop sharing after files have been sent** seçeneğini etkin tutun.
4. Sharing'i başlatın ve complete onion URL bilgisini zaten authenticated olan bir E2EE channel üzerinden gönderin. Bunu email, issue tracker veya public chat'lere yapıştırmayın.
5. Recipient, URL'yi Tor Browser'da açar, beklenen filenames/size bilgilerini sender ile doğrular ve download yapar.
6. File'ın kendisi security boundary olduğunda integrity için her iki taraf, önceden kararlaştırılmış veya ayrı bir kanaldan iletilmiş SHA-256 digest bilgisini karşılaştırır.
7. OnionShare'ın download sonrasında durduğunu doğrulayın; aksi durumda manuel olarak durdurun ve application'ı kapatın.
8. Staged copy'yi retention policy'ye göre silin ve istemeden filename disclosure oluşup oluşmadığını görmek için OnionShare history/log settings ayarlarını inceleyin.

### CLI workflow

Official CLI, files bilgilerini positional arguments olarak kabul eder ve varsayılan tek completed share sonrasında durur. Official CLI/Tor kurulmuş bir host üzerinde:
```bash
# Inspect the installed version and options first
onionshare-cli --help

# Share one sanitized file; stop after one hour even if unused
onionshare-cli --auto-stop-timer 3600 ./staging/report-clean.pdf
```
Ortaya çıkan tam URL'yi güvenli şekilde iletin. Tehdit modeli ortaya çıkan maruziyeti açıkça gerektirmedikçe `--public`, `--no-autostop-sharing`, ayrıntılı dosya adı logging'i veya persistence eklemeyin.<sup>[[7]](#references)</sup>

Alınan belgeleri hostile kabul edin. Bunları kimlik barındıran host üzerinde açmak yerine disposable bir VM/Dangerzone tarzı renderer içinde açın.

## `age` ile bir dosyayı bağımsız olarak şifreleme

Transport-independent encryption, bir storage/email provider'ın nesneyi görebileceği durumlarda kullanışlıdır. Sender, recipient, boyut, zamanlama veya dosya adını gizlemez; bunlar ayrıca ele alınmalıdır.

### Alıcı kurulumu
```bash
# Creates a secret identity file; protect its permissions and backup
age-keygen -o recipient-identity.txt

# Derive a public recipient file safe to share
age-keygen -y recipient-identity.txt > recipient-public.txt
```
Genel alıcı dizesini ikinci bir kanal üzerinden doğrulayın. Ardından gönderici şunu çalıştırır:
```bash
age -R recipient-public.txt -o package.tar.age package.tar
```
Alıcı yeni bir path'e şifresini çözer:
```bash
age --decrypt -i recipient-identity.txt -o package-restored.tar package.tar.age
```
Resmi CLI, `-o` seçeneğinin mevcut bir çıktının üzerine yazdığı konusunda uyarır; bu nedenle yeni bir dizin kullanın ve dosyayı taşımadan önce digest/içeriği doğrulayın.<sup>[[8]](#references)</sup> Kimlik dosyasını ciphertext ile asla göndermeyin.

## Tekrarlanabilir dosya temizleme pipeline'ı

Metadata temizleme biçime özeldir. Özgünlüğün, adli incelemenin veya delil zincirinin önemli olduğu durumlarda şifrelenmiş orijinali koruyun; bir kopya üzerinde işlem yapın.

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
Bu, ExifTool'un daha güvenli JPEG yönergelerini izler: her tag'i körü körüne kaldırmak renk bilgilerini de kaldırabilir.<sup>[[9]](#references)</sup> Ardından pikselleri yüzler, yansımalar, ekranlar, önemli noktalar ve benzersiz hasar/gürültü desenleri açısından görsel olarak inceleyin.

### Office/PDF iş akışı

1. Düzenlenebilir orijinali şifrelenmiş halde ve yayınlama bağlamından çevrimdışı tutun.
2. Authoring application içinde yorumları, izlenen değişiklikleri, gizli slaytları/sayfaları, gömülü dosyaları, kişisel şablonları ve document properties'i kaldırın.
3. Özel ve temiz bir profile'dan yeni bir PDF export edin; bir cloud printer'a “print” etmeyin.
4. Hem format-aware araçlarla hem de disposable bir visual renderer ile inceleyin:
```bash
exiftool -a -u -g1 ./clean/report.pdf
pdfinfo ./clean/report.pdf
```
5. Oluşturulan çıktıda adları, yolları, e-posta adreslerini ve revizyon metnini arayın. Rasterization etkin yapıları kaldırabilir, ancak erişilebilirliği/aramayı olumsuz etkiler; ayrıca görünür içeriği veya yazım tarzını kaldırmaz.
6. Final artifact'ı hash'leyin ve yayınlama compartment'ı üzerinden **yalnızca** bu kopyayı transfer edin.

## Privacy Pass: service designers için anonim authorization

Privacy Pass, token **issuance** ve **redemption** işlemlerini birbirinden ayırır. Bir origin, client'ın issuer tarafından onaylanmış bir token'a sahip olduğunu öğrenebilir; ancak client'ın belirli issuance etkileşimini öğrenemez. Bir token'ı yeniden kullanmak, benzersiz metadata, zamanlama veya collusion, linkability'yi yeniden oluşturabilir.<sup>[[10]](#references)</sup>

Güvenli deployment pattern:

1. Token'ın kanıtladığı ifadeyi (örneğin rate-limit uygunluğu) tanımlayın; gizli bir global identity tanımlamayın.
2. Standardize edilmiş architecture ve issuance protocol'lerini kullanın; blind-signature cryptography'yi sıfırdan implement etmeyin.
3. İstenen property bunu gerektiriyorsa issuer/attester ve origin administration'ı ayırın.
4. Public/private token metadata'yı minimize edin ve anonymity set'lerinin yeterince büyük olduğundan emin olun.
5. Desteklendiği durumlarda kullanım öncesinde batch'ler issue edin; böylece issuance time, redemption time ile basitçe eşleştirilemez.
6. Her token'ı yalnızca bir kez redeem edin, origin-bound challenge'ı validate edin ve süresi dolmuş token state'ini silin.
7. Cookie'lerin, IP logging'in ve application account'larının token privacy property'sini fark edilmeden geçersiz kılmasını önleyin.
8. Issuer ve origin log'larının timing, metadata veya unique error'lar kullanarak kontrollü bir issuance ve redemption event'ini birleştirip birleştiremeyeceğini test edin.

Privacy Pass bir application feature'dır; kullanıcının rastgele bir account'a sonradan ekleyebileceği bir şey değildir.

## Communications verification checklist

- [ ] Contact/invitation/key bağımsız olarak authenticated edildi.
- [ ] Phone number, username, profile, group ve contact-upload exposure anlaşıldı.
- [ ] Direct IP, relay, Tor, push-provider ve local-radio observer'lar listelendi.
- [ ] Notification preview'ları, wearable'lar, linked desktop'lar ve backup'lar test edildi.
- [ ] File'lar sanitize edildi, gerektiğinde encrypted edildi ve disposable context içinde açıldı.
- [ ] Recovery, ilgisiz identity'leri birbirine bağlamadan çalışıyor.
- [ ] Log'lar, history ve temporary share service'leri için bir shutdown/retention rule mevcut.

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

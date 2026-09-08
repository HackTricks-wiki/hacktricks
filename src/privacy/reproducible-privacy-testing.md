# Reproducible Privacy Testing

Bir privacy kurulumu bağlandığında tamamlanmış olmaz. İddia edilen sınırı normal kullanım, arıza, kurtarma ve kaldırma sırasında test edildiğinde tamamlanmış olur. Kendi sahip olduğunuz veya inceleme yetkinizin bulunduğu altyapıya karşı test yapın; herkese açık “leak test” siteleri başka bir gözlemciye dönüşür.

## Küçük bir yetkili test ortamı oluşturun

İdeal olarak ayrı provider/network'ler üzerinde üç rol kullanın:
```text
operator endpoint ---- privacy path ---- owned web/DNS endpoint
|                                      |
local packet/route view                 server-side logs
|
controller/provider dashboards and payment/account records
```
Her testten önce şunları kaydedin:

- test ID'si, UTC başlangıç/bitiş zamanı, operatör ve yetkilendirme;
- endpoint/OS/client sürümleri ve yapılandırma hash'i;
- beklenen IPv4, IPv6, DNS, TLS, hesap, ödeme ve fiziksel gözlemler;
- hangi log'ların inceleneceği ve bunların saatleri/zaman dilimleri;
- başarılı/başarısız kuralı ve teardown zamanı.

Önce hiçbir zaman hassas bir kimliği test etmeyin. Tester'a ait sentetik bir hesap ve zararsız, benzersiz canary değerleri kullanın.

## Network-path testi

### 1. Baseline'ı yakalayın

Privacy path'i etkinleştirmeden önce yerel route'ları ve resolver'ları kaydedin:
```bash
ip route
ip -6 route
resolvectl status
```
macOS'ta `route -n get default`, `netstat -rn -f inet6` ve `scutil --dns` kullanın. Çıktıyı yalnızca kontrollü kanıt deposuna kaydedin; çıktı yerel tanımlayıcılar içerebilir.

### 2. Bağlanın ve yönlendirmeyi inceleyin

VPN/Tor/iş yükü namespace'ini etkinleştirin, ardından kontrollü genel adresler için seçilen rotayı kontrol edin:
```bash
ip route get 192.0.2.10
ip -6 route get 2001:db8::10
```
Dokümantasyon adreslerini test sunucusu adresleriyle değiştirin. Seçilen arayüzün/tablonun tasarımla eşleştiğini doğrulayın.

### 3. Her iki uçtan gözlemleyin

Sahip olunan endpoint'in URL'sini ayarlayın, ardından benzersiz ve zararsız bir yol isteyin:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl --fail --show-error --silent \
"${PRIVACY_TEST_URL}/privacy-check/run-20260907-001"
```
Gerçekten tester tarafından kontrol edilen bir domain, authenticated TLS ve hassas olmayan bir path token kullanın. Sunucu logunu şunlar için inceleyin:

- kaynak adresi/ASN ve beklenen egress;
- IPv4 ve IPv6 arasındaki fark;
- endpoint'te görülebilen Host/SNI davranışı;
- user agent ve application header'ları;
- kesin zaman ve request'in yeniden kullanımı.

Sözde ayrıştırılmış bir request'e `X-Forwarded-For`, benzersiz debug header'ları veya kimlik içeren cookie'ler eklemeyin.

### 4. Sahip olduğunuz bir canary ile DNS'i test edin

Sorgu loglarını kontrol ettiğiniz authoritative bir test zone yapılandırın. Compartment üzerinden benzersiz, rastgele bir label sorgulayın:
```bash
dig run-20260907-001.privacy-test.example A
dig run-20260907-001.privacy-test.example AAAA
```
Yetkili log'u inceleyin. Bu log normalde istemciyi değil, recursive resolver'ı görür. Bu resolver'ı amaçlanan VPN/Tor/application DNS tasarımıyla karşılaştırın. Rastgele bir public DNS leak sitesi gerekli değildir.

### 5. fail-closed davranışını test edin

Size ait endpoint'i hedefleyen zararsız bir request loop'u çalışır durumda tutun, ardından privacy path'i durdurun. Workload fiziksel bir interface'e geçmek yerine başarısız olmalıdır. Her iki address family'yi ve DNS'i kontrol edin:
```bash
: "${PRIVACY_TEST_URL:?Set PRIVACY_TEST_URL to the owned HTTPS endpoint}"
curl -4 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v4"
curl -6 --connect-timeout 5 "${PRIVACY_TEST_URL}/run-v6"
dig privacy-test.example
```
Şu durumlarda tekrarlayın:

- tunnel işlemi çökmesi;
- Wi-Fi'dan Ethernet'e veya hotspot'a geçiş;
- uyku/uyanma;
- DHCP yenilemesi;
- captive-portal durumu;
- provider yeniden bağlanması/anahtar süresinin dolması.

Bir Linux namespace/container için tunnel'ını durdurun ve başka bir varsayılan rota veya resolver olmadığını doğrulayın:
```bash
ip netns exec privacy-workload ip route
ip netns exec privacy-workload ip -6 route
ip netns exec privacy-workload resolvectl status
```
İsimler ve komutlar deployment'a göre değişir. Console recovery olmadan bunları uzak bir production host'una yapıştırmayın.

### 6. Yerel socket'leri ve paketleri inceleme

Yetkilendirme ile hangi process/interface'in gerçekten iletişim kurduğunu kontrol edin:
```bash
ss -tpn
ss -upn
sudo tcpdump -ni any 'host TEST_SERVER_IP'
```
`TEST_SERVER_IP` ifadesini açıkça sahip olunan adresle değiştirin; ilgisiz kullanıcıların geniş kapsamlı yakalanmasından kaçının. Fiziksel arayüz tunnel/bridge peer'ını görmeli, clear destination trafiği ise yalnızca amaçlanan katmanda bulunmalıdır.

## Tor ve onion-service testi

1. Tor Browser'da Tor Project bağlantı kontrolünü ziyaret edin ve Tor kullanımını doğrulayın. Bunu kimlik kanıtı olarak değerlendirmeyin.<sup>[[1]](#references)</sup>
2. Sahip olunan HTTPS endpoint'ini benzersiz bir canary ile ziyaret edin ve endpoint'in bir Tor exit gördüğünü, tanımlayıcı cookie'lerin bulunmadığını ve standart browser context'inin kullanıldığını doğrulayın.
3. **New Identity** seçeneğini belirleyin, farklı bir canary ile tekrar ziyaret edin ve yerel durumun beklendiği gibi temizlendiğini doğrulayın. Exit IP değişimi garanti edilmez ve New Identity'nin amacı değildir.
4. Bir onion service için erişimi yalnızca Tor Browser üzerinden gerçekleştirin. Yetkili bir external scan ile service host üzerinde public listener bulunmadığını doğrulayın ve application response'larının public hostname/IP içermediğini kontrol edin.
5. Origin outbound DNS/HTTP isteklerini, template'leri, error page'lerini, email/webhook'ları ve third-party asset'leri inceleyin. Herhangi bir direct fetch, origin'i veya operator account'unu açığa çıkarabilir.
6. Client authorization etkinse, credential'ı olmayan temiz bir Tor Browser'ın bağlanamadığını ve credential'ı olanın bağlanabildiğini doğrulayın.
7. Bir test authorization key'ini rotate edin ve revoked client'ın onion identity'sini değiştirmeden erişimini kaybettiğini doğrulayın.

## Browser-compartment testi

Test için gereken alanları yalnızca kaydeden ve retention period'u kısa olan kontrollü bir sayfa oluşturun. Personal ve privacy compartment'larını şu unsurlar açısından karşılaştırın:

- cookie'ler/local storage/service worker'lar ve cache;
- browser sync/login durumu;
- language, time zone, screen/window dimensions ve font'lar;
- WebRTC/network candidate'ları;
- permission'lar ve extension'ların görünür kıldığı değişiklikler;
- server üzerindeki TLS/HTTP user-agent verileri.

Tor Browser'ı "daha random" hâle getirmeye çalışmayın. Pass koşulu, standard anonymity set'ine benzerlik ve personal state'in bulunmamasıdır; personal browser'dan maksimum farklılık değildir.

Copy/paste, drag/drop, indirilen dosyanın açılması, password-manager önerileri ve identity-provider button'larını test edin. Bunlar compartment'lar arasındaki sık görülen bridge'lerdir.

## Operating-system isolation testi

### Tails

1. Persistent Storage olmayan bir session'da benign bir dosya/canary ile başlayın.
2. Tamamen shutdown gerçekleştirin, reboot edin ve dosyanın kaybolduğunu doğrulayın.
3. Yalnızca gereken tek bir persistence category'yi etkinleştirin, tekrarlayın ve ilgisiz browser/application state'inin tutulmadığını doğrulayın.
4. Portal login sonrasında Unsafe Browser'ın sensitive activity için kullanılamadığını ve Tor application'larının normal şekilde yeniden bağlandığını doğrulayın.

### Whonix/Qubes

1. Gateway/net qube'u durdurun ve Workstation/app qube'un IPv4, IPv6 veya DNS'e erişemediğini kanıtlayın.
2. Yalnızca açıkça yapılandırılmış inter-qube clipboard/file path'ini deneyin ve diğer shared-folder/device path'lerinin bulunmadığını doğrulayın.
3. Benign bir test document'ını disposable qube'da açın, kapatın ve durumunun kaybolduğunu doğrulayın.
4. Vault qube'un NetVM'inin olmadığını ve template/default değişikliği yoluyla bir NetVM edinemediğini kontrol edin.
5. Bir test VM'ini snapshot/restore edin ve identity-bearing state'in beklenmedik şekilde geri dönüp dönmediğini inceleyin.

## Communications metadata testi

Seçilen her messenger için:

1. Kontrollü cihazlarda yalnızca test amacıyla kullanılacak participant'lar oluşturun.
2. Registration için nelerin gerektiğini kaydedin: phone, app-store account, IP, push service, username veya invitation.
3. Notification preview'larını, linked desktop'ları, wearable'ları ve backup'ları incelerken bir benign message gönderin.
4. Safety/security code'larını bağımsız bir path üzerinden doğrulayın.
5. Receipt/push'ı devre dışı bırakın veya Tor/local transport'ları teker teker etkinleştirin ve reliability/metadata değişikliklerini gözlemleyin.
6. Bir test backup'ını export veya restore edin ve tam olarak hangi profile, contact'ları ve history'yi içerdiğini belgeleyin.
7. Bir test cihazını kaybedin/revoke edin ve kalan participant'ların beklenen key/device değişikliğini gördüğünü doğrulayın.

İlgisiz kişilerle iletişime geçerek veya abusive traffic oluşturarak test yapmayın.

## File-sanitization testi

1. Orijinali encrypted evidence storage içinde hash'leyip koruyun:
```bash
sha256sum ./original/file > ./original/file.sha256
```
2. [Privacy-Preserving Communications and Sharing](privacy-preserving-communications-and-sharing.md) bölümündeki formata özgü süreci kullanarak temizlenmiş bir kopya oluşturun.
3. Metadata envanterlerini karşılaştırın:
```bash
exiftool -a -u -g1 ./original/file
exiftool -a -u -g1 ./clean/file
```
4. Kopyayı disposable bir context içinde render edin/açın. Gizli içeriği, ekleri, linkleri, formları, katmanları, küçük resimleri ve görsel identifiers'ları kontrol edin.
5. Yalnızca staged kopyada bilinen canary author/email/path string'lerini arayın.
6. Final çıktının hash'ini alın ve yayımlanacak dosyanın tam olarak doğrulanması için ikinci bir kişinin kontrol etmesini sağlayın.

ExifTool çıktısında bulunmaması anonimlik kanıtı değildir; format internals, pikseller, düzyazı ve dağıtım kayıtları varlığını sürdürür.

## Ödeme gizliliği testi

İzin verilen en küçük tutarı veya resmi bir test network/sandbox kullanın:

1. Payer, payee/merchant, issuer/exchange, network/node, public ledger ve accountant/controller için beklenen görünümü yazın.
2. Yanlış kimlik kullanmadan benzersiz bir test invoice/merchant context oluşturun.
3. Bir kez ödeme yapın; ardından **kendi** receipt'inizi, statement'ınızı, merchant dashboard'unuzu, wallet/node log'unuzu ve uygun olduğunda public-chain görünümünü toplayın.
4. Tutarın, timestamp'in, address/token'ın, account'un, IP/device'ın, teslimatın ve refund route'unun observer table ile eşleşip eşleşmediğini kontrol edin.
5. Bitcoin için wallet'ın coin-control görünümünde address reuse, selected inputs, change ve sonraki consolidation işlemlerini inceleyin.
6. Shielded protocol'lerde gerçek pool/path'i ve bir viewing key'in neyi ortaya çıkardığını doğrulayın; gizliliği wallet branding'inden çıkarsamayın.
7. E-cash/Taler için küçük bir değerle backup/recovery, refund ve redemption işlemlerini test edin; mint/exchange/federation boundary kayıtlarını belgeleyin.
8. Bir virtual card/test credential'ı revoke edin ve meşru refund işlemleri anlaşılmış olarak sonraki authorization'ın başarısız olduğunu doğrulayın.
9. Gerekli vergi/authorization kanıtlarını encrypted olarak reconcile edin ve saklayın.

Bir “privacy test” olarak asla circular transfer, threshold-splitting, fake purchase veya şüpheli refund oluşturmayın.

## Yetkilendirilmiş red-team accountability drill

Exercise'dan önce bir tabletop ve technical drill gerçekleştirin:

1. Bir operator, onaylanan her source path'ten benign bir canary başlatır.
2. Hedef SOC, blind testing amaçlanıyorsa operator identity'sini almadan tespit ettiği şeyleri kaydeder.
3. Exercise controller, escrowed map ve signed job record'dan source → engagement → operator eşlemesini çözer.
4. Controller emergency stop'u gönderir; operator ve infrastructure owner, ROE süresi içinde shutdown işlemini gösterir.
5. Provider abuse, doğru 24/7 contact bilgisini ve authorization reference'ı alır.
6. Evidence; gereksiz payload content'i saklamadan target'ı, zamanı, tool/job'u ve operator'ı gösterir.
7. İkinci bir operator credential revocation ve resource teardown işlemlerini doğrular.

SOC kişisel/home infrastructure'ı kolayca görebiliyorsa **veya** controller source'u hızlıca attribute edip durduramıyorsa readiness review'ı başarısız sayın.

## Test record template
```text
Test ID / date (UTC):
Authorization / owner:
Claim under test:
Expected observers:
Endpoint + versions:
Configuration hash:
Normal result:
Failure/reconnect result:
Server/provider/account evidence:
Unexpected linkage:
Pass/fail:
Remediation + retest ID:
Evidence retention/deletion date:
```
## References

- [1] [Tor Project — Bağlantı kontrolü](https://check.torproject.org/)
- [2] [WireGuard — Yönlendirme ve Ağ Ad Alanları](https://www.wireguard.com/netns/)
- [3] [ExifTool — SSS ve metadata rehberi](https://exiftool.org/faq.html)
- [4] [NIST SP 800-115 — Bilgi Güvenliği Testi ve Değerlendirmesi için Teknik Rehber](https://csrc.nist.gov/pubs/sp/800/115/final)

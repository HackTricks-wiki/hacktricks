# Open vSwitch'in iletilen skb işaretçisini kaldırarak ESP üzerinden page-cache'e yazması

{{#include ../../../banners/hacktricks-training.md}}

Yararlı bir Linux kernel exploit tekniği, **yabancı fragment'leri kaldırmadan skb'den sahiplik meta verilerini temizlemek**, ardından bu skb'yi yerinde yazan bir tüketiciye yönlendirmektir. Open vSwitch (OVS) örneğinde, başarısız bir userspace upcall, hâlâ etkin olan `MSG_ZEROCOPY` skb'sinden `SKBFL_SHARED_FRAG` işaretçisini temizler; ardından ESP, salt okunur bir dosyanın page-cache folio'sunun üzerine doğrudan şifre çözme işlemi yapar. Bu, CVE-2026-90049, CVE-2026-89487 ve CVE-2026-80977 kapsamında izlenen, deterministik bir yerel page-cache yazma olanağı sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

Bu, klasik bellek bozulmasından ziyade Copy Fail/Dirty Frag sınıfında bir sorundur: yarış koşulu veya adres ifşası gerekmez, dosyanın okunabilir olması yeterlidir ve değişen baytlar diskte değil page cache'de bulunur.<sup>[[2]](#references)[[3]](#references)</sup>

## Güvenlik değişmezi: yabancı fragment'ler işaretli kalmalıdır

`SKBFL_SHARED_FRAG`, skb fragment'inin tüketicinin özel olarak sahip olmadığı bir depolamaya işaret edebileceğini, yerinde çalışan tüketicilere bildirir. `esp_input()` içindeki ESP fast path'i, doğrusal olmayan ve klonlanmamış bir skb'nin şifre çözme işlemini yerinde ancak `skb_has_shared_frag()` false olduğunda yapabilir; aksi durumda `skb_cow_data()` önce özel depolama oluşturur. Bu tüketici tarafı kontrolü Dirty Frag sonrasında eklenmiştir.<sup>[[5]](#references)</sup>

Dolayısıyla değişmez iki bağımsız bölümden oluşur:<sup>[[2]](#references)[[4]](#references)[[5]](#references)</sup>

1. Yerinde yazan kod, `SKBFL_SHARED_FRAG` değerini kontrol etmeli ve değişiklik yapmadan önce paylaşılan veriyi kopyalamalıdır.
2. Her klonlama, birleştirme, aktarım veya iletme yolu, yabancı sayfa bağlı kaldığı sürece işaretçiyi korumalıdır.

Fragnesia, `skb_try_coalesce()` içinde fragment tanımlayıcılarını taşırken ikinci kuralı ihlal etti. OVS yolu ise ince bir fark gösterir: fragment'i hiç aktarmaz; işaretçiyi **özgün skb üzerinde yerinde temizler ve ardından skb'yi iletmeye devam eder**.<sup>[[2]](#references)[[4]](#references)</sup>

## Ayrıcalıksız OVS erişilebilirliği

OVS'nin kernel datapath'i `ovs_datapath`, `ovs_vport`, `ovs_flow` ve `ovs_packet` gibi generic-netlink aileleri üzerinden denetlenir. Değişiklik yapan işlemleri namespace-aware `GENL_UNS_ADMIN_PERM` kullanır; bu nedenle `unshare -Urn` altında çalışan bir süreç, kendi network namespace'i içinde datapath oluşturmak, veth bağlamak ve flow eylemleri yüklemek için gereken `CAP_NET_ADMIN` yetkisini elde eder. OVS ailesinin çözümlenmesi `openvswitch.ko` modülünün otomatik yüklenmesine de neden olabilir; bu saldırı yüzeyi için host üzerinde `CAP_SYS_MODULE`, `ovs-vsctl` ve `ovs-vswitchd` gerekmez.<sup>[[2]](#references)[[7]](#references)</sup>

Önemli fark, iki upcall türü arasındadır:<sup>[[2]](#references)[[7]](#references)</sup>

- Bir **flow miss**, paketi `ovs-vswitchd`'ye gönderir; upcall başarısız olursa paket normalde düşürülür.
- Açık bir `OVS_ACTION_ATTR_USERSPACE` eylemi, ödünç alınmış bir kopyayı seçilen port ID'sine gönderir ve ardından sonraki eylemleri özgün skb üzerinde yürütür.

Bu nedenle saldırgan aşağıdaki yapıda bir flow yükleyebilir:<sup>[[1]](#references)[[2]](#references)</sup>

```text
in_port(1),ipv4 -> USERSPACE(pid=<unbound-portid>), OUTPUT(0)
```

Seçilen port ID'sine sahip bir listener olmadığından userspace action beklenen şekilde başarısız olurken, sonraki `OUTPUT` action özgün paketi canlı tutar.<sup>[[1]](#references)[[2]](#references)</sup>

## Kök neden: Hayatta kalan bir pakette `skb_tx_error()`

Savunmasız OVS upcall hata yolu `skb_tx_error(skb)` çağırır. Bu yardımcı, başarısız bir iletimden sonra skb'nin serbest bırakılacağı durumlar için tasarlanmıştır; `SKBFL_SHARED_FRAG` bayrağını da tarihsel olarak kaldıran bir bayrak maskesine sahip olan `skb_zcopy_clear()` aracılığıyla zerocopy muhasebesini tamamlar. OVS, userspace-action hatasını yok sayıp action listesini yürütmeye devam ederek yardımcının yaşam süresi sözleşmesini ihlal eder.<sup>[[1]](#references)[[2]](#references)</sup>

İstismar edilebilir durum geçişi şöyledir:<sup>[[2]](#references)</sup>

```text
before failed upcall: flags=0xb, nr_frags=1, page-cache folio attached
skb_tx_error():       zerocopy flags, including SHARED_FRAG, are cleared
after failed upcall:  flags=0x0, nr_frags=1, same folio still attached
OUTPUT:               unmarked skb continues to local ESP input
```

Bu yalnızca `skb_zcopy()` zerocopy state bulduğunda çalışır. Yalnızca `SKBFL_SHARED_FRAG` taşıyan bir fragment yeterli değildir; `MSG_ZEROCOPY` kullanışlıdır çünkü `SKBFL_ZEROCOPY_ENABLE | SKBFL_SHARED_FRAG` oluşturur ve ayrıca `SKBFL_DONT_ORPHAN` ayarlar. İkincisi, OVS userspace copy sırasında `skb_orphan_frags()`'ın yabancı sayfaları değiştirmesini engeller.<sup>[[2]](#references)[[3]](#references)</sup>

## write primitive oluşturma

Uçtan uca tetikleyici şu bileşenlerden oluşur.<sup>[[2]](#references)[[3]](#references)</sup>

1. `unshare -Urn` ile private user ve network namespace'lere girin.
2. Okunabilir hedef dosyayı `PROT_READ | MAP_SHARED` ile map edin.
3. Ayrı bir sender netns ve bir veth pair kullanın; yerel loopback ödünç alınan sayfaları kopyalayarak primitive'i bozar.
4. Bir OVS datapath ve başarısız `USERSPACE`-ardından-`OUTPUT` flow oluşturun.
5. `rfc4106(gcm(aes))` ve UDP portu 4500 kullanan transport-mode ESP-in-UDP XFRM state kurun.
6. `[ESP header | mapped file bytes | invalid ICV]` biçiminde bir iovec içeren tek bir `MSG_ZEROCOPY` datagramı gönderin.

XFRM state, 20 baytlık AES-128-GCM keying material kullanır: 16 bayt AES key ve ardından dört baytlık RFC 4106 salt. Seçilen sekiz baytlık explicit IV için payload confidentiality, `salt || IV || be32(2)` counter block'u ile başlar; counter değeri 1 ise authentication result maskelenir.<sup>[[2]](#references)[[6]](#references)</sup>

```bash
ip xfrm state add src 10.99.99.1 dst 10.99.99.2 proto esp \
  spi 0x42434445 mode transport \
  aead 'rfc4106(gcm(aes))' \
  0x000102030405060708090a0b0c0d0e0f11223344 128 \
  encap espinudp 4500 4500 0.0.0.0
```

OVS işaretleyiciyi kaldırdığında ESP, kopyalama yapmayan yolunu izler ve dosya destekli parça üzerinde `plaintext = ciphertext XOR keystream` işlemini gerçekleştirir. Kimlik doğrulaması bu dönüşümden **sonra** denetlendiğinden, tümü sıfırlardan oluşan geçersiz bir ICV, ancak page-cache baytları zaten değiştikten sonra paketin `-EBADMSG` ile başarısız olmasına neden olur.<sup>[[2]](#references)</sup>

### GCM'yi seçilen baytlara dönüştürme

Geçerli `C` baytı ve istenen `P` baytı için ilk payload keystream baytının `C XOR P` olması gerekir. AES anahtarı ve salt sabitken, 16 bitlik bir explicit IV sonekini tarayarak mümkün olan her ilk keystream baytı için bir sonek önceden hesaplayın:<sup>[[2]](#references)[[3]](#references)[[6]](#references)</sup>

```text
for n in 0..0xffff:
    iv = 0xcccccccc || 0x0000 || be16(n)
    k0 = AES_K(salt || iv || be32(2))[0]
    first_suffix_for[k0] ??= n
```

Genel kullanıma açık uygulama, şifreli metni 32 baytla sınırlar ve her paket için dosya parçasını bir bayt ilerletir. Seçilen ilk bayt, önceki paketin ilk yan hasar baytının üzerine yazar; her paketten önce `pread()` ile `C` yenilenir, aynı baytlar atlanır ve yazmaların istenen aralığı aşmaması için son paket kısaltılır. Böylece 256 girişli bir arama tablosu, bu temel işlemi farklı her bayt için yaklaşık bir paket kullanarak bayt düzeyinde, seçilen içerikle bir page-cache yazımına dönüştürür.<sup>[[2]](#references)[[3]](#references)</sup>

## Root yetkisine page-cache yazımı

Uygulanabilir bir hedef, mevcut bir setuid-root yürütülebilir dosyasıdır. PoC, ilk 160 baytı sabit adresli tek bir `PT_LOAD` içeren, `PT_INTERP` içermeyen ve `execve("/bin/sh", ...)` çağırmadan önce `setuid(0)` çağıran kod barındıran eksiksiz bir statik ELF ile değiştirir. Bu yöntem, özgün ikilinin giriş noktası, PIE yerleşimi, dinamik yükleyici veya yer değiştirmeleri hakkında varsayımlarda bulunma gereğini ortadan kaldırır.<sup>[[2]](#references)[[3]](#references)</sup>

Değişiklik, page cache ad alanlarına bağlı olmadığından kullanıcı ad alanları arasında görünür. Değiştirilen folio dirty olarak işaretlenmez ve bu nedenle diske geri yazılmaz; hedefi bellekteyken çalıştırın, ardından sonraki okumaların özgün disk içeriğini yüklemesi için geçici bozulmayı `posix_fadvise(..., POSIX_FADV_DONTNEED)` ile atın.<sup>[[2]](#references)[[3]](#references)</sup>

## Maruziyet kontrolleri ve azaltma

Önce kullanılan vendor kernel’i kontrol edin. İlgili maruziyet koşulları; ayrıcalıksız kullanıcı ad alanlarının, OVS’nin kullanılabilir veya bellekte bulunur durumda olmasının ve bir ESP uygulamasının kullanılabilir olmasının gerekliliğidir.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
unshare -Urn true 2>/dev/null && echo 'user+net namespaces available'
sysctl user.max_user_namespaces kernel.unprivileged_userns_clone \
  kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
lsmod | grep openvswitch
modprobe -n -v openvswitch esp4 esp6 2>/dev/null
modinfo esp4 esp6 2>/dev/null | grep -E '^(name|alias):'
```

Düzeltme serisinin tamamını içeren bir kernel sürümüne yükseltin; son düzeltme, yeniden dolaşım yolunu da kapsar ve paylaşılan `skb_shinfo()` durumunun değiştirilmesini önler. Ayrıca `skb_zerocopy()` içindeki bağlantılı bir açığı da kapatır.<sup>[[1]](#references)[[2]](#references)</sup>

OVS kullanılmıyorsa yalnızca `blacklist` kullanmaya güvenmek yerine bir modprobe `install` kuralıyla hem alias üzerinden hem de adla yüklenmesini engelleyin. Host IPsec sonlandırmıyorsa ve ESP modülerse, aynı denetim şifre çözme hedefini de kaldırabilir.<sup>[[2]](#references)</sup>

```conf
# /etc/modprobe.d/disable-unused-network-surfaces.conf
install openvswitch /bin/false
install esp4 /bin/false
install esp6 /bin/false
```

Bu kurallar, bir modül zaten yüklüyse veya özellik kernel'e yerleşikse işe yaramaz. Ayrıcalıksız user namespace'leri devre dışı bırakmak, namespace yeteneği kaynağını da ortadan kaldırır; ancak tarayıcıları, Flatpak'i, Podman'ı ve diğer sandbox/container iş yüklerini bozabilir.<sup>[[2]](#references)</sup>

## İnceleme dersleri

Zero-copy networking'i denetlerken aramayı yalnızca fragment'leri kopyalayan veya taşıyan yardımcılarla sınırlamayın. Gruplandırılmış flag'leri temizleyen hata/tamamlama yardımcılarını da belirleyin ve ardından her çağıranın belgelenmiş skb yaşam döngüsü sözleşmesine uyduğunu doğrulayın. Zero-copy yaşam döngüsü bitleriyle gruplandırılmış bir sayfa sahipliği biti, temizleme kodu doğrudan bir fragment'e erişmese bile güvenlik açısından hassastır.<sup>[[1]](#references)[[2]](#references)</sup>

Sağlam bir düzeltme, skb'nin hayatta kalabileceği tüm yolları (action continuation ve recirculation dahil) kapsamalı ve klonların `skb_shinfo()` yapısını paylaştığını hesaba katmalıdır. Tüketici tarafında, kimlik doğrulama hatası, yerinde çalışan bir AEAD dönüşümünün önceden gerçekleştirdiği açık metin yazımlarını geri almaz; bu nedenle yabancı depolama kontrolleri, şifre çözme başlamadan önce yapılmalıdır.<sup>[[1]](#references)[[2]](#references)</sup>

## References

- [1] [Doyensec netdev düzeltme serisi: net: iletilen bir skb'den zerocopy frag işaretçilerini kaldırmayın](https://lore.kernel.org/netdev/4B5CCA6E-2C49-4F86-8C4E-E1BE15C16C0A@doyensec.com/T/#t)
- [2] [Doyensec: Open vSwitch iletilen skb işaretçilerinin kaldırılması, deterministik ESP Page-Cache LPE'yi mümkün kılıyor](https://blog.doyensec.com/2026/09/17/ovs.html)
- [3] [Doyensec `ovs-pagecache-write` kavram kanıtı](https://github.com/doyensec/ovs-pagecache-write)
- [4] [Orijinal Fragnesia birleştirme yolu için Linux düzeltmesi (`f84eca581739`)](https://github.com/torvalds/linux/commit/f84eca5817390257cef78013d0112481c503b4a3)
- [5] [Linux ESP tüketici tarafı paylaşılan fragment kontrolü (`f4c50a4034e6`)](https://github.com/torvalds/linux/commit/f4c50a4034e6)
- [6] [RFC 4106: IPsec ESP'de Galois/Counter Mode (GCM) Kullanımı](https://datatracker.ietf.org/doc/html/rfc4106)
- [7] [Open vSwitch kernel datapath belgeleri](https://docs.openvswitch.org/en/latest/topics/datapath/)
{{#include ../../../banners/hacktricks-training.md}}

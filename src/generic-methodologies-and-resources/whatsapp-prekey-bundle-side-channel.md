# WhatsApp Prekey Bundle Tükenmesi ve Yenilenmesi Side Channel

{{#include ../banners/hacktricks-training.md}}

WhatsApp, her cihaz için bir identity key, bir signed prekey ve tek kullanımlık prekey rezervi saklar. Bir cihazın bundle'ını almak, isteği gönderen taraf hiç mesaj göndermese bile sunucuda tutulan tek kullanımlık bir prekey'i tüketir. Bu, WhatsApp hesabına ve hedefin telefon numarasına sahip bir saldırgana, [istemci teslimat bildirimi zamanlamasından](side-channel-attacks-on-messaging-protocols.md) farklı, **sunucu tarafında** bir probe sağlar. Tek kullanımlık bir prekey'in bulunmaması, yeni kurulan bir oturumun *ilk* mesajları için forward secrecy'yi de zayıflatır; ancak tek başına plaintext'i açığa çıkarmaz.<sup>[[1]](#references)[[2]](#references)</sup>

## Hedefin cihaz bundle'larını inceleme

[Prekey Pogo aracı](https://github.com/sbaresearch/prekey-pogo), WhatsApp companion oturumu olarak eşleşir ve **manuel** cihaz ve prekey sorgularını destekler. Aracı bir test hesabıyla eşleştirin, ardından etkileşimli `target`, `devices`, `prekey` (birincil cihaz) ve `combine` (tüm cihazlar) komutlarını kullanın. Yayımlanan araç, otomatik tüketme ve sunucuyu tıkama işlevlerini özellikle içermez.<sup>[[1]](#references)[[3]](#references)</sup>

```bash
git clone https://github.com/sbaresearch/prekey-pogo
cd prekey-pogo
./setup.sh
go run .
```

Her yanıt için cihaz JID'sini, bundle timestamp `t` değerini, signed-prekey ID `skey.id` değerini ve one-time `key.id` değerinin mevcut olup olmadığını kaydedin. Cihaz ID'si `0` olan telefon, sıfır olmayan ID'ler ise companion cihazlardır. Makalede test edilen uygulamalarda, başlangıçtaki signed-prekey ID'si bazı istemcileri de ayırt eder: Android `0` ile başlar, iOS ve macOS rastgele bir değer kullanır, WhatsApp Web ve Windows Desktop ise `1` ile başlar. Bunu değişmez bir protokol kuralı değil, uygulama parmak izi olarak değerlendirin.<sup>[[1]](#references)</sup>

## Refill işlemlerini bir çevrimiçi durum oracle'ına dönüştürme

Önce kontrolünüzdeki bir cihazda kalibrasyon yapın: Sunucu one-time `key` döndürmeyi bırakana kadar cihazın bundle'ını tekrar tekrar isteyin; son timestamp ve key ID'lerini not edin. Hedef cihaz için, kontrollü bir aralık sonunda key havuzunu tüketip yeniden sorgulayın: Yeni bir one-time key ve ilerlemiş bir bundle timestamp, cihazın yeni bir batch yüklediğini gösterir. Bildirilen WhatsApp testlerinde sunucu, kalan key sayısı 11'in altına düştüğünde refill isteğinde bulundu ve istemciler 812 yeni key yükledi. Telefonu companion cihazlardan ayırt etmek için bu işlemi her cihaz JID'si için ayrı ayrı uygulayın. Geciken bir refill, cihazın çevrimdışı olduğunu yalnızca **düşündürür**: Arka plan planlaması, ağ kesintisi ve istemciye özgü refill gecikmesi aynı gözleme yol açabilir. Receipt RTT'den farklı olarak bu probe, teslim edilmiş bir ciphertext veya kurban tarafında bir onay gerektirmez.<sup>[[1]](#references)[[2]](#references)</sup>

Her sorgu bir one-time key tüketir; bu nedenle sürekli çalışan bir oracle için tekrarlanan prekey retrieval yapabilen özel bir istemci gerekir; herkese açık artifact yalnızca manuel sorguları gösterir. Rezervi boş tutmak, diğer kullanıcıların one-time prekey olmadan yeni oturumlar kurmasına yol açabilir. Bu, yeni bir ratchet adımına kadar ilk mesajların forward secrecy korumasını azaltır; ancak kaydedilmiş ciphertext'i istismar etmek için ayrıca E2EE ciphertext'e erişim ve ilgili uzun ve orta vadeli özel anahtarların daha sonra ele geçirilmesi gerekir. Önceden kurulmuş oturumların güvenlik seviyesi otomatik olarak düşürülmez.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [Prekey Pogo: WhatsApp'ın Handshake Mekanizmasındaki Güvenlik ve Gizlilik Sorunlarını İnceleme](https://www.usenix.org/system/files/woot25-gegenhuber.pdf)
- [2] [X3DH Key Agreement Protocol](https://signal.org/docs/specifications/x3dh/)
- [3] [Prekey Pogo artifact'ları](https://github.com/sbaresearch/prekey-pogo)
{{#include ../banners/hacktricks-training.md}}

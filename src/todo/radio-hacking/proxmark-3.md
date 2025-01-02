# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Атака на RFID системи з Proxmark3

Перше, що вам потрібно зробити, це мати [**Proxmark3**](https://proxmark.com) та [**встановити програмне забезпечення та його залежності**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Атака на MIFARE Classic 1KB

Він має **16 секторів**, кожен з яких має **4 блоки**, а кожен блок містить **16B**. UID знаходиться в секторі 0, блоці 0 (і не може бути змінений).\
Щоб отримати доступ до кожного сектора, вам потрібно **2 ключі** (**A** та **B**), які зберігаються в **блоці 3 кожного сектора** (секторний трейлер). Секторний трейлер також зберігає **біти доступу**, які надають **права на читання та запис** на **кожен блок** за допомогою 2 ключів.\
2 ключі корисні для надання прав на читання, якщо ви знаєте перший, і на запис, якщо ви знаєте другий (наприклад).

Можна виконати кілька атак
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
Proxmark3 дозволяє виконувати інші дії, такі як **перехоплення** комунікації **мітка з зчитувачем**, щоб спробувати знайти чутливі дані. У цій карті ви можете просто перехопити комунікацію та обчислити використаний ключ, оскільки **використовувані криптографічні операції є слабкими**, і знаючи відкритий та зашифрований текст, ви можете його обчислити (інструмент `mfkey64`).

### Сирі команди

Системи IoT іноді використовують **небрендовані або некомерційні мітки**. У цьому випадку ви можете використовувати Proxmark3 для відправки користувацьких **сирих команд до міток**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
З цією інформацією ви можете спробувати знайти інформацію про картку та про спосіб зв'язку з нею. Proxmark3 дозволяє надсилати сирі команди, такі як: `hf 14a raw -p -b 7 26`

### Скрипти

Програмне забезпечення Proxmark3 постачається з попередньо завантаженим списком **автоматизаційних скриптів**, які ви можете використовувати для виконання простих завдань. Щоб отримати повний список, використовуйте команду `script list`. Далі використовуйте команду `script run`, за якою слідує назва скрипта:
```
proxmark3> script run mfkeys
```
Ви можете створити скрипт для **fuzz tag readers**, тому, щоб скопіювати дані **діючої картки**, просто напишіть **Lua скрипт**, який **рандомізує** один або кілька випадкових **байтів** і перевіряє, чи **збій** зчитувача з будь-якою ітерацією.

{{#include ../../banners/hacktricks-training.md}}

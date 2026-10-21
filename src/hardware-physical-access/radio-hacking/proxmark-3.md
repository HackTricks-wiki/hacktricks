# Proxmark 3

{{#include ../../banners/hacktricks-training.md}}

## Атака на RFID-системи за допомогою Proxmark3

Встановіть клієнт RRG/Iceman Proxmark3, який активно підтримується, і відповідну прошивку, а потім перевірте синтаксис команд для цієї збірки, оскільки наведені нижче старі команди могли змінитися.<sup>[[1]](#references)[[5]](#references)</sup>

### Атака на MIFARE Classic 1KB

MIFARE Classic 1K має **16 секторів**, кожен із яких містить **4 блоки** по **16 байтів**. Блок виробника 0 містить UID/дані виробника та доступний лише для читання на оригінальних картках NXP; спеціальні клоновані картки або картки «magic» можуть дозволяти його перезаписувати.<sup>[[1]](#references)[[2]](#references)</sup>\
Щоб отримати доступ до кожного сектора, потрібні **2 ключі** (**A** і **B**), які зберігаються в **блоці 3 кожного сектора** (трейлер сектора). Трейлер сектора також зберігає **біти доступу**, які визначають дозволи на **читання та запис** для **кожного блока** за допомогою двох ключів.\
Два ключі корисні, наприклад, для надання дозволу на читання, якщо ви знаєте перший ключ, і на запис, якщо знаєте другий.

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

Proxmark3 дає змогу виконувати й інші дії, наприклад **перехоплювати** **зв’язок між міткою та зчитувачем**, щоб спробувати знайти конфіденційні дані. У цьому випадку можна просто перехопити зв’язок і обчислити використаний ключ, оскільки **застосовані криптографічні операції слабкі**, а знаючи відкритий текст і шифротекст, його можна обчислити (інструмент `mfkey64`).<sup>[[3]](#references)</sup>

#### Короткий робочий процес MiFare Classic для зловживання системами збереження вартості

Послідовність дій для відновлення ключа, порівняння балансу, перевірки поля цілісності та клонування UID, включно з журналом команд клієнта Proxmark3 і обмеженнями магічних карток, описано в [офлайновому втручанні в збережену вартість MiFare Classic](pentesting-rfid.md#mifare-classic-offline-stored-value-tampering-broken-crypto1).

### Необроблені команди

В IoT-системах іноді використовують **небрендовані або некомерційні мітки**. У такому разі можна використовувати Proxmark3 для надсилання до **міток спеціальних необроблених команд**.

```bash
proxmark3> hf search UID : 80 55 4b 6c ATQA : 00 04
SAK : 08 [2]
TYPE : NXP MIFARE CLASSIC 1k | Plus 2k SL1
  proprietary non iso14443-4 card found, RATS not supported
  No chinese magic backdoor command detected
  Prng detection: WEAK
  Valid ISO14443A Tag Found - Quitting Search
```

За допомогою цієї інформації можна спробувати знайти відомості про картку та спосіб зв’язку з нею. Proxmark3 дає змогу надсилати raw-команди, наприклад: `hf 14a raw -p -b 7 26`

### Скрипти

Програмне забезпечення Proxmark3 містить попередньо завантажений список **скриптів автоматизації**, які можна використовувати для виконання простих завдань. Щоб отримати повний список, скористайтеся командою `script list`. Потім скористайтеся командою `script run`, вказавши назву скрипту:

```
proxmark3> script run mfkeys
```

Ви можете створити скрипт для **fuzz-тестування зчитувачів міток**: скопіюйте дані з **валідної картки**, напишіть **Lua-скрипт**, який **рандомізує** один або кілька випадкових **байтів**, і перевірте, чи не **аварійно завершує роботу зчитувач** під час будь-якої ітерації.

## References

- [1] [Вікі Proxmark3: HF MIFARE](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Mifare)
- [2] [Вікі Proxmark3: HF Magic cards](https://github.com/RfidResearchGroup/proxmark3/wiki/HF-Magic-cards)
- [3] [Заява NXP щодо MIFARE Classic Crypto1](https://www.mifare.net/en/products/chip-card-ics/mifare-classic/security-statement-on-crypto1-implementations/)
- [4] [Експлуатація вразливості NFC-картки в KioSoft Stored Value (SEC Consult)](https://sec-consult.com/vulnerability-lab/advisory/nfc-card-vulnerability-exploitation-leading-to-free-top-up-kiosoft-payment-solution/)
- [5] [RRG/Iceman Proxmark3 — встановлення в Linux](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
{{#include ../../banners/hacktricks-training.md}}

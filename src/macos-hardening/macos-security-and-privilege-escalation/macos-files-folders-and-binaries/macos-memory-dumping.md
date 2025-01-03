# macOS Memory Dumping

{{#include ../../../banners/hacktricks-training.md}}

## Memory Artifacts

### Swap Files

Файли обміну, такі як `/private/var/vm/swapfile0`, слугують як **кеші, коли фізична пам'ять заповнена**. Коли в фізичній пам'яті більше немає місця, її дані передаються до файлу обміну, а потім повертаються до фізичної пам'яті за потреби. Може бути кілька файлів обміну з іменами, такими як swapfile0, swapfile1 тощо.

### Hibernate Image

Файл, розташований за адресою `/private/var/vm/sleepimage`, є критично важливим під час **режиму гібернації**. **Дані з пам'яті зберігаються в цьому файлі, коли OS X переходить в гібернацію**. Після пробудження комп'ютера система отримує дані пам'яті з цього файлу, що дозволяє користувачу продовжити з того місця, де він зупинився.

Варто зазначити, що на сучасних системах MacOS цей файл зазвичай зашифрований з міркувань безпеки, що ускладнює відновлення.

- Щоб перевірити, чи увімкнено шифрування для sleepimage, можна виконати команду `sysctl vm.swapusage`. Це покаже, чи файл зашифрований.

### Memory Pressure Logs

Ще один важливий файл, пов'язаний з пам'яттю, в системах MacOS - це **журнал тиску пам'яті**. Ці журнали розташовані в `/var/log` і містять детальну інформацію про використання пам'яті системи та події тиску. Вони можуть бути особливо корисними для діагностики проблем, пов'язаних з пам'яттю, або для розуміння того, як система управляє пам'яттю з часом.

## Dumping memory with osxpmem

Щоб скинути пам'ять на машині MacOS, ви можете використовувати [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip).

**Примітка**: Наступні інструкції працюватимуть лише для Mac з архітектурою Intel. Цей інструмент зараз архівований, а останній реліз був у 2017 році. Бінарний файл, завантажений за допомогою наведених нижче інструкцій, націлений на чіпи Intel, оскільки Apple Silicon не існувала в 2017 році. Можливо, ви зможете скомпілювати бінарний файл для архітектури arm64, але вам доведеться спробувати самостійно.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Якщо ви знайдете цю помилку: `osxpmem.app/MacPmem.kext failed to load - (libkern/kext) authentication failure (file ownership/permissions); check the system/kernel logs for errors or try kextutil(8)` Ви можете виправити це, виконавши:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Інші помилки** можуть бути виправлені **дозволивши завантаження kext** в "Безпека та конфіденційність --> Загальні", просто **дозвольте** це.

Ви також можете використовувати цей **однорядник** для завантаження програми, завантаження kext і дампу пам'яті:
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{{#include ../../../banners/hacktricks-training.md}}

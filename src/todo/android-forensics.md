# Forensics Android

{{#include ../banners/hacktricks-training.md}}

## Заблокований пристрій

Надавайте перевагу методам отримання даних, які зберігають стан пристрою, і документуйте кожну дію. Якщо пристрій заблокований, доступні варіанти залежать від моделі, версії Android, рівня патчів і того, чи було налаштовано доступ до вилучення пристрою. NIST рекомендує обирати метод відповідно до пристрою та повноважень для проведення дослідження.<sup>[[1]](#references)</sup>

- Перевірте, чи було ввімкнено USB debugging і чи авторизовано робочу станцію для збору даних. Доступ через ADB зазвичай потребує, щоб користувач розблокував пристрій і підтвердив RSA-ключ робочої станції.<sup>[[3]](#references)</sup>
- Визначте, чи залишається доступною біометрична автентифікація відповідно до чинних правових і процедурних норм.
- **Smudge attack** може виявити графічний шаблон розблокування за залишками на екрані, хоча подальші дотики та очищення знижують його надійність.<sup>[[2]](#references)</sup>
- Використовуйте комерційні або дослідницькі інструменти обходу блокування лише тоді, коли вони явно підтримують конкретний пристрій і збірку ПЗ.

## Отримання даних

На старіших пристроях застарілий [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) може створити файл `.backup`, який можна розпакувати за допомогою Android Backup Extractor:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Не припускайте, що це охоплює кожен застосунок. ADB позначає цю команду як застарілу, а Android 12 виключає дані із застосунків, орієнтованих на API level 31 або новішу версію, якщо застосунок не є debuggable.<sup>[[4]](#references)</sup>

### Root або фізичний debug-доступ

Маючи root-доступ до живого пристрою, спочатку проінвентаризуйте розділи та монтування; наведені нижче команди не застосовуються безпосередньо до фізичного JTAG-зняття даних. Правильний block device залежить від апаратного забезпечення, тому не припускайте, що це завжди `mmcblk0`. Створюйте образ лише з перевіреного джерела на окреме сховище:<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Хешуйте результат і зафіксуйте точну команду, ідентифікатори пристрою, час і всі зміни, внесені під час збору даних.<sup>[[1]](#references)</sup>

### Пам'ять

LiME може отримувати фізичну пам'ять із Linux і деяких Android-пристроїв, але його kernel module має бути зібраний для цільового kernel і завантажений із достатніми привілеями. Підпис модулів, kernel lockdown і сучасні механізми захисту Android можуть перешкоджати його завантаженню.<sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Рекомендації щодо forensic-аналізу мобільних пристроїв](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Smudge Attacks on Smartphone Touch Screens](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Android 12 ADB backup restriction](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Android Backup Extractor](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}

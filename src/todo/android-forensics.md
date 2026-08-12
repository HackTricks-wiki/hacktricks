# Android Forensics

{{#include ../banners/hacktricks-training.md}}

## Locked Device

Надавайте перевагу методам отримання даних, які зберігають стан пристрою, і документуйте кожну дію. Якщо пристрій заблокований, доступні варіанти залежать від моделі, версії Android, рівня виправлень безпеки та того, чи було налаштовано доступ до вилучення пристрою. NIST рекомендує обирати метод відповідно до пристрою та повноважень, на підставі яких проводиться дослідження.<sup>[[1]](#references)</sup>

- Перевірте, чи було ввімкнено USB debugging і чи авторизовано вже робочу станцію для вилучення даних. Для доступу через ADB зазвичай потрібно, щоб користувач розблокував пристрій і підтвердив RSA-ключ робочої станції.<sup>[[3]](#references)</sup>
- Визначте, чи залишається доступною біометрична автентифікація відповідно до застосовних правових і процедурних правил.
- **Smudge attack** може виявити графічний unlock pattern за залишками на екрані, хоча наступні дотики та очищення знижують його надійність.<sup>[[2]](#references)</sup>
- Якщо авторизований інструментарій підтримує конкретний пристрій і версію програмного забезпечення, він може спробувати відновити або brute force PIN, пароль чи pattern. Перевірка облікових даних із використанням апаратного захисту, затримки між спробами та політики стирання даних роблять це специфічним для кожного пристрою, тому не замінюйте техніку або результат для iPhone доказами того, що Android-пристрій підтримується.<sup>[[1]](#references)</sup>

## Data acquisition

На старіших пристроях застарілий [ADB backup](../mobile-pentesting/android-app-pentesting/adb-commands.md#backup) може створити файл `.backup`, який Android Backup Extractor може розпакувати:<sup>[[6]](#references)</sup>
```bash
java -jar abe.jar unpack file.backup file.tar
```
Не припускайте, що це охоплює кожен застосунок. ADB позначає команду як deprecated, а Android 12 виключає дані застосунків, орієнтованих на API level 31 або новіший, якщо застосунок не є debuggable.<sup>[[4]](#references)</sup>

### Root або фізичний debug-доступ

Маючи root-доступ до працюючого пристрою, спочатку складіть перелік розділів і монтувань; наведені нижче команди не застосовуються безпосередньо до фізичного JTAG-зняття даних. Правильний block device залежить від обладнання, тому не припускайте, що це завжди `mmcblk0`. Створюйте образ лише з перевіреного джерела на окреме сховище:<sup>[[1]](#references)</sup>

JTAG-зняття даних натомість використовує апаратний інтерфейс тестового доступу пристрою та сумісне обладнання для зняття даних, щоб зчитувати доступну пам'ять. Розпіновка, підтримка chipset, стан пристрою та розрізнення між volatile і non-volatile цілями залежать від пристрою; документуйте апаратний шлях і використовуйте перевірену процедуру для цієї моделі.<sup>[[1]](#references)</sup>
```bash
cat /proc/partitions
df /data
dd if=/dev/block/<verified-device> of=/sdcard/device.img bs=4096
```
Наприклад, якщо інвентаризація розділів підтверджує, що `/dev/block/mmcblk0` є всім флеш-пристроєм, а в місці призначення достатньо вільного простору, початкова команда отримання образу стає такою:<sup>[[1]](#references)</sup>
```bash
dd if=/dev/block/mmcblk0 of=/sdcard/blk0.img bs=4096
```
Тут `df /data` допомагає пов’язати `/data` із його змонтованою файловою системою; це не слід сприймати як доказ того, що `mmcblk0` є правильним джерелом усього пристрою або що `4096` є єдиним допустимим розміром блоку `dd`.

Обчисліть хеш результату та зафіксуйте точну команду, ідентифікатори пристрою, час і будь-які зміни, внесені під час отримання даних.<sup>[[1]](#references)</sup>

### Пам’ять

LiME може отримувати фізичну пам’ять із Linux і деяких Android-пристроїв, але його kernel module має бути зібраний для цільового kernel і завантажений із достатніми привілеями. Підписування модулів, kernel lockdown і сучасні механізми захисту Android можуть перешкоджати його завантаженню.<sup>[[5]](#references)</sup>

Android workflow цього проєкту передає відповідний module за допомогою ADB, перенаправляє TCP-порт, завантажує module з root shell і захоплює потік на хості, де проводиться examination:<sup>[[5]](#references)</sup>
```bash
adb push lime.ko /sdcard/lime.ko
adb forward tcp:4444 tcp:4444
adb shell
su
insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
```

```bash
nc localhost 4444 > ram.lime
```
LiME може натомість записувати дані у сховище пристрою за допомогою `path=/sdcard/ram.lime`, але це змінює сховище пристрою та потребує достатнього вільного місця. Зафіксуйте цей побічний ефект і обчисліть хеш отриманого образу.<sup>[[1]](#references)</sup><sup>[[5]](#references)</sup>

## References

- [1] [NIST SP 800-101 Rev. 1 - Рекомендації щодо судової експертизи мобільних пристроїв](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-101r1.pdf)
- [2] [USENIX WOOT 2010 - Атаки Smudge на сенсорні екрани смартфонів](https://www.usenix.org/legacy/event/woot10/tech/full_papers/Aviv.pdf)
- [3] [Android Developers - Android Debug Bridge](https://developer.android.com/tools/adb)
- [4] [Android Developers - Обмеження резервного копіювання ADB в Android 12](https://developer.android.com/about/versions/12/behavior-changes-12#adb-backup-restrictions)
- [5] [504ensicsLabs - Linux Memory Extractor (LiME)](https://github.com/504ensicsLabs/LiME)
- [6] [Розпаковувач резервних копій Android](https://sourceforge.net/projects/adbextractor/)
{{#include ../banners/hacktricks-training.md}}

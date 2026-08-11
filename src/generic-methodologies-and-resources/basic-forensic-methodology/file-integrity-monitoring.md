# Моніторинг цілісності файлів

{{#include ../../banners/hacktricks-training.md}}

## Базовий стан

Базовий стан передбачає створення знімка певних частин системи, щоб **порівняти його з майбутнім станом і виявити зміни**.

Наприклад, можна обчислити та зберегти хеш кожного файла файлової системи, щоб визначити, які файли було змінено.\
Це також можна зробити для створених облікових записів користувачів, запущених процесів, запущених служб та будь-яких інших компонентів, які не повинні часто або взагалі змінюватися.

**Корисний базовий стан** зазвичай зберігає не лише дайджест: також варто відстежувати дозволи, власника, групу, часові мітки, inode, ціль symlink, ACL та вибрані розширені атрибути.<sup>[[4]](#references)</sup> З точки зору пошуку атакувальників це допомагає виявляти **маніпуляції лише з дозволами**, **атомарну заміну файлів** і **забезпечення persistence через змінені файли служб/unit**, навіть якщо хеш вмісту не є першою зміненою ознакою.

### Моніторинг цілісності файлів

Моніторинг цілісності файлів (FIM) — це критично важлива техніка безпеки, яка захищає IT-середовища та дані шляхом відстеження змін у файлах. Зазвичай він поєднує:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Порівняння з базовим станом:** Збереження метаданих і криптографічних контрольних сум (бажано `SHA-256` або кращих) для майбутніх порівнянь.
2. **Сповіщення в реальному часі:** Підписка на нативні події файлової системи ОС, щоб знати, **який файл змінився, коли саме та, в ідеалі, який процес/користувач здійснив до нього доступ**.
3. **Періодичне повторне сканування:** Відновлення впевненості після перезавантажень, втрати подій, збоїв agent або навмисної anti-forensic activity.

Для threat hunting FIM зазвичай ефективніший, якщо зосереджений на **шляхах із високою цінністю**, таких як:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, розташування cron, SSH material, PAM modules, web roots
- Розташування persistence у Windows, бінарні файли служб, файли scheduled task, startup folders
- Writable layers контейнерів і bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Backend збору має значення:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: прості та поширені, але ліміти watch можуть бути вичерпані, а деякі edge cases можуть залишатися непоміченими.
- **`auditd` / audit framework**: кращий варіант, коли потрібно знати, **хто змінив файл** (login UID, process ID і process name).
- **`eBPF` / `kprobes`**: новіші варіанти, які використовуються сучасними FIM stacks для збагачення подій і зменшення частини operational pain, властивого звичайним розгортанням `inotify`.

Деякі практичні нюанси:<sup>[[1]](#references)[[5]](#references)</sup>

- Якщо програма **замінює** файл за схемою `write temp -> rename`, відстеження самого файла може стати неефективним. **Відстежуйте батьківський каталог**, а не лише файл.
- Колектори на основі `inotify` можуть пропускати події або працювати гірше на **величезних деревах каталогів**, під час **активності з hard-link**, або після **видалення файла, за яким ведеться спостереження**.
- Дуже великі рекурсивні набори watch можуть непомітно завершуватися помилкою, якщо значення `fs.inotify.max_user_watches`, `max_user_instances` або `max_queued_events` є надто низькими.
- Для моніторингу на основі `inotify` network filesystems є blind spot, оскільки про віддалені зміни не повідомляється.

Приклад baseline + verification за допомогою AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Приклад конфігурації `osquery` FIM, зосередженої на шляхах закріплення зловмисника:<sup>[[1]](#references)</sup>
```json
{
"schedule": {
"fim": {
"query": "SELECT * FROM file_events;",
"interval": 300,
"removed": false
}
},
"file_paths": {
"etc": ["/etc/%%"],
"systemd": ["/etc/systemd/system/%%", "/usr/lib/systemd/system/%%"],
"ssh": ["/root/.ssh/%%", "/home/%/.ssh/%%"]
}
}
```
Якщо вам потрібна **атрибуція процесу**, а не лише зміни на рівні шляхів, надавайте перевагу телеметрії на основі аудиту, такій як `osquery` `process_file_events` або режим Wazuh `whodata`.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

### Windows

У Windows FIM є ефективнішим, коли ви поєднуєте **журнали змін** із **телеметрією процесів/файлів із високою інформативністю**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** надає постійний журнал змін файлів для кожного тому.
- **Sysmon Event ID 11** корисний для виявлення створення/перезапису файлів.
- **Sysmon Event ID 2** допомагає виявляти **timestomping**.
- **Sysmon Event ID 15** корисний для **іменованих альтернативних потоків даних (ADS)**, таких як `Zone.Identifier` або приховані потоки payload.

Приклади швидкого тріажу USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Для глибшого розгляду ідей у сфері anti-forensics щодо **timestamp manipulation**, **ADS abuse** і **USN tampering** див. [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Контейнери

FIM контейнерів часто не відстежує фактичний шлях запису. У Docker `overlay2` файлова система контейнера поєднує доступні лише для читання шари образу `lowerdir` із доступним для запису **верхнім шаром** (`upperdir`/`diff`), а записи у файли образу копіюються до цього верхнього шару.<sup>[[8]](#references)</sup> Тому:

- Моніторинг лише шляхів **усередині** недовговічного контейнера може не виявити зміни після повторного створення контейнера.
- Моніторинг **шляху на хості**, який є основою для доступного для запису шару, або відповідного bind-mounted тому, часто є кориснішим.
- FIM шарів образу відрізняється від FIM файлової системи запущеного контейнера.

## Нотатки з пошуку, орієнтованого на зловмисників

- Відстежуйте **визначення служб** і **планувальники завдань** так само ретельно, як і бінарні файли. Зловмисники часто забезпечують persistence, змінюючи unit-файл, запис cron або XML-файл завдання, а не модифікуючи `/bin/sshd`.
- Одного хешу вмісту недостатньо. Багато компрометацій спочатку проявляються як **зміни owner/mode/xattr/ACL**.
- Якщо ви підозрюєте зріле вторгнення, використовуйте обидва підходи: **FIM у реальному часі** для виявлення свіжої активності та **порівняння з cold baseline** із надійного носія.
- Якщо зловмисник отримав root або можливість виконання коду на рівні ядра, вважайте FIM-агент і його базу даних ненадійними. За можливості зберігайте журнали та baseline віддалено або на носіях, доступних лише для читання.<sup>[[4]](#references)</sup>

## Інструменти

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Моніторинг цілісності файлів за допомогою osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Трасування Linux: сценарій використання моніторингу цілісності файлів (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Моніторинг цілісності файлів Wazuh (режими Syscheck і whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Посібник AIDE, версія 0.16.2](https://aide.github.io/doc/)
- [5] [Сторінка посібника Linux для inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Драйвер сховища OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Розширені налаштування Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}

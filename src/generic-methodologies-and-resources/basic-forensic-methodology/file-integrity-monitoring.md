# Моніторинг цілісності файлів

## Базовий стан

Базовий стан полягає у створенні знімка певних частин системи, щоб **порівняти його з майбутнім станом і виявити зміни**.

Наприклад, можна обчислити та зберегти хеш кожного файла файлової системи, щоб визначити, які файли було змінено.\
Це також можна зробити для створених облікових записів користувачів, запущених процесів, запущених служб та будь-чого іншого, що не повинно часто або взагалі змінюватися.

**Корисний базовий стан** зазвичай зберігає не лише дайджест: також варто відстежувати дозволи, власника, групу, часові мітки, inode, ціль symlink, ACLs і вибрані розширені атрибути.<sup>[[4]](#references)</sup> З погляду пошуку атакувальників це допомагає виявляти **втручання лише в дозволи**, **атомарну заміну файлів** і **закріплення через змінені файли служб/unit**, навіть якщо хеш вмісту не є першою зміненою характеристикою.

### Моніторинг цілісності файлів

File Integrity Monitoring (FIM) — це критично важлива техніка безпеки, яка захищає IT-середовища та дані шляхом відстеження змін у файлах. Зазвичай вона поєднує:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Порівняння з базовим станом:** зберігання метаданих і криптографічних контрольних сум (надавайте перевагу `SHA-256` або надійнішому алгоритму) для майбутніх порівнянь.
2. **Сповіщення в реальному часі:** підписка на нативні події файлової системи ОС, щоб знати, **який файл і коли було змінено та, в ідеалі, який процес/користувач його змінив**.
3. **Періодичне повторне сканування:** відновлення достовірності після перезавантажень, втрати подій, відмов агентів або навмисної anti-forensic activity.

Для threat hunting FIM зазвичай корисніше зосереджувати на **шляхах із високою цінністю**, таких як:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- unit-файли `systemd`, розташування cron, матеріали SSH, модулі PAM, корені вебсайтів
- розташування persistence у Windows, бінарні файли служб, файли запланованих завдань, теки автозапуску
- доступні для запису шари контейнерів і secrets/configuration, підключені через bind mount

## Backend-и реального часу та сліпі зони

### Linux

Backend збору даних має значення:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: прості та поширені, але ліміти спостереження можуть бути вичерпані, а деякі крайні випадки залишаються непоміченими.
- **`auditd` / audit framework**: кращий варіант, коли потрібно знати, **хто змінив файл** (login UID, ID процесу та назву процесу).
- **`eBPF` / `kprobes`**: новіші варіанти, які використовуються сучасними FIM stacks для доповнення подій і зменшення частини операційних проблем звичайних розгортань `inotify`.

Деякі практичні нюанси:<sup>[[1]](#references)[[5]](#references)</sup>

- Якщо програма **замінює** файл за допомогою `write temp -> rename`, спостереження безпосередньо за файлом може стати марним. **Спостерігайте за батьківською директорією**, а не лише за файлом.
- Збирачі на основі `inotify` можуть пропускати події або працювати нестабільно у випадку **величезних дерев директорій**, **операцій із hard link** або після **видалення файла, за яким ведеться спостереження**.
- Дуже великі рекурсивні набори спостереження можуть непомітно завершуватися невдачею, якщо `fs.inotify.max_user_watches`, `max_user_instances` або `max_queued_events` мають надто низькі значення.
- Для моніторингу на основі `inotify` мережеві файлові системи є сліпою зоною, оскільки про віддалені зміни не повідомляється.

Приклад базового стану та перевірки за допомогою AIDE:<sup>[[4]](#references)</sup>
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Приклад конфігурації FIM для `osquery`, зосередженої на шляхах закріплення зловмисника:<sup>[[1]](#references)</sup>
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

У Windows FIM є ефективнішим, якщо поєднати **журнали змін** із **телеметрією процесів/файлів із високою інформативністю**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** надає постійний журнал змін файлів для кожного тому.
- **Sysmon Event ID 11** корисний для виявлення створення/перезапису файлів.
- **Sysmon Event ID 2** допомагає виявляти **timestomping**.
- **Sysmon Event ID 15** корисний для **іменованих альтернативних потоків даних (ADS)**, таких як `Zone.Identifier`, або прихованих потоків payload.

Короткі приклади тріажу USN:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Для глибшого розуміння anti-forensic ідей щодо **timestamp manipulation**, **ADS abuse** та **USN tampering** див. [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Контейнери

FIM контейнерів часто не охоплює реальний шлях запису. У Docker `overlay2` файлова система контейнера поєднує доступні лише для читання шари образу `lowerdir` із доступним для запису **верхнім шаром** (`upperdir`/`diff`), а записи до файлів образу копіюються у цей верхній шар.<sup>[[8]](#references)</sup> Тому:

- Моніторинг лише шляхів **усередині** короткоживучого контейнера може не виявити зміни після повторного створення контейнера.
- Моніторинг **шляху на хості**, що є основою для доступного для запису шару, або відповідного bind-mounted volume часто є кориснішим.
- FIM для шарів образу відрізняється від FIM для файлової системи запущеного контейнера.

## Нотатки щодо полювання, орієнтованого на зловмисників

- Відстежуйте **визначення сервісів** і **планувальники завдань** так само ретельно, як і бінарні файли. Зловмисники часто забезпечують persistence, змінюючи unit-файл, cron-запис або XML завдання, а не модифікуючи `/bin/sshd`.
- Одного хешу вмісту недостатньо. Багато компрометацій спочатку проявляються як **відхилення owner/mode/xattr/ACL**.
- Якщо ви підозрюєте тривале проникнення, робіть обидва: **real-time FIM** для виявлення нової активності та **порівняння з cold baseline** із довіреного носія.
- Якщо зловмисник отримав root або kernel execution, вважайте FIM-агент і його базу даних недовіреними. За можливості зберігайте логи та baseline віддалено або на носіях, доступних лише для читання.<sup>[[4]](#references)</sup>

## Інструменти

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html).<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## References

- [1] [Моніторинг цілісності файлів за допомогою osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Трасування Linux: приклад використання моніторингу цілісності файлів (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Моніторинг цілісності файлів Wazuh (режими Syscheck і whodata)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [4] [Посібник AIDE версії 0.16.2](https://aide.github.io/doc/)
- [5] [Сторінка посібника Linux для inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Драйвер сховища OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Розширені налаштування Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
{{#include ../../banners/hacktricks-training.md}}

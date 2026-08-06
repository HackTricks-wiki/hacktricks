# Моніторинг цілісності файлів

{{#include ../../banners/hacktricks-training.md}}

## Базова конфігурація

Базова конфігурація полягає у створенні знімка певних частин системи, щоб **порівняти його з майбутнім станом і виявити зміни**.

Наприклад, можна обчислити та зберегти хеш кожного файла файлової системи, щоб визначити, які файли були змінені.\
Так само можна відстежувати створені облікові записи користувачів, запущені процеси, запущені служби та будь-які інші об'єкти, які не повинні часто або взагалі змінюватися.

**Корисна базова конфігурація** зазвичай зберігає не лише дайджест: також варто відстежувати дозволи, власника, групу, часові мітки, inode, ціль symlink, ACL та вибрані розширені атрибути. З погляду пошуку атак це допомагає виявляти **втручання лише в дозволи**, **атомарну заміну файлів** і **закріплення через змінені service/unit-файли**, навіть якщо хеш вмісту не є першою зміненою ознакою.

### Моніторинг цілісності файлів

File Integrity Monitoring (FIM) — це критично важлива техніка безпеки, яка захищає IT-середовища та дані, відстежуючи зміни у файлах. Зазвичай вона поєднує:

1. **Порівняння з базовою конфігурацією:** Зберігайте метадані та криптографічні контрольні суми (надавайте перевагу `SHA-256` або кращому алгоритму) для майбутніх порівнянь.
2. **Сповіщення в реальному часі:** Підписуйтеся на нативні для ОС події файлової системи, щоб знати, **який файл змінився, коли саме та, в ідеалі, який процес/користувач взаємодіяв із ним**.
3. **Періодичне повторне сканування:** Відновлюйте впевненість у цілісності після перезавантажень, втрати подій, простоїв агента або навмисної anti-forensic активності.

Для threat hunting FIM зазвичай корисніший, якщо зосереджений на **шляхах із високою цінністю**, таких як:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, розташування cron, SSH-матеріали, PAM-модулі, web roots
- Розташування persistence у Windows, бінарні файли служб, файли scheduled tasks, startup folders
- Доступні для запису шари контейнерів і bind-mounted secrets/configuration

## Backends реального часу та сліпі зони

### Linux

Backend збору даних має значення:<sup>[[2]](#references)</sup>

- **`inotify` / `fsnotify`**: прості та поширені, але ліміти watch можуть бути вичерпані, а деякі edge cases пропускаються.
- **`auditd` / audit framework**: кращий варіант, коли потрібно знати, **хто змінив файл** (`auid`, process, pid, executable).
- **`eBPF` / `kprobes`**: новіші options, які використовуються сучасними FIM stacks для збагачення подій і зменшення частини операційних проблем звичайних deployments на базі `inotify`.

Деякі практичні нюанси:<sup>[[1]](#references)</sup>

- Якщо програма **замінює** файл за допомогою `write temp -> rename`, відстеження самого файла може втратити корисність. **Відстежуйте батьківський каталог**, а не лише файл.
- Collectors на базі `inotify` можуть пропускати події або працювати гірше у випадку **величезних дерев каталогів**, **операцій із hard links** або після **видалення файла, що відстежувався**.
- Дуже великі рекурсивні набори watch можуть непомітно завершуватися з помилкою, якщо `fs.inotify.max_user_watches`, `max_user_instances` або `max_queued_events` мають надто низькі значення.
- Network filesystems зазвичай є поганими цілями для FIM із низьким рівнем шуму.

Приклад baseline + verification за допомогою AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Приклад конфігурації FIM в `osquery`, зосередженої на шляхах persistence зловмисника:<sup>[[1]](#references)</sup>
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
Якщо вам потрібна **атрибуція процесу**, а не лише зміни на рівні шляхів, надавайте перевагу телеметрії на основі аудиту, такій як `osquery` `process_file_events` або режим Wazuh `whodata`.<sup>[[1]](#references)[[3]](#references)</sup>

### Windows

У Windows FIM є ефективнішим, якщо поєднати **журнали змін** із **телеметрією процесів/файлів із високою інформативністю**:

- **NTFS USN Journal** надає постійний журнал змін файлів для кожного тому.
- **Sysmon Event ID 11** корисний для виявлення створення/перезапису файлів.
- **Sysmon Event ID 2** допомагає виявляти **timestomping**.
- **Sysmon Event ID 15** корисний для **іменованих альтернативних потоків даних (ADS)**, таких як `Zone.Identifier` або приховані потоки payload.

Короткі приклади USN triage:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Для глибшого ознайомлення з ідеями **timestamp manipulation**, **ADS abuse** і **USN tampering** див. [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Контейнери

FIM контейнерів часто не відстежує справжній шлях запису. У Docker `overlay2` зміни фіксуються у **writable upper layer** контейнера (`upperdir`/`diff`), а не в доступних лише для читання шарах образу. Тому:

- Моніторинг лише шляхів **усередині** короткоживучого контейнера може не виявити зміни після повторного створення контейнера.
- Моніторинг **шляху на хості**, який відповідає writable layer, або відповідного bind-mounted volume часто є кориснішим.
- FIM для шарів образу відрізняється від FIM для файлової системи запущеного контейнера.

## Нотатки для полювання, орієнтованого на атакувальника

- Відстежуйте **визначення служб** і **планувальники завдань** так само ретельно, як і бінарні файли. Атакувальники часто забезпечують persistence, змінюючи unit file, cron entry або task XML, а не модифікуючи `/bin/sshd`.
- Самого content hash недостатньо. Багато компрометацій спочатку проявляються як **дрейф owner/mode/xattr/ACL**.
- Якщо ви підозрюєте зріле вторгнення, робіть обидва типи перевірок: **real-time FIM** для виявлення свіжої активності та **порівняння з cold baseline** із trusted media.
- Якщо атакувальник отримав root або kernel execution, вважайте, що FIM agent, його database і навіть event source могли бути змінені. За можливості зберігайте логи та baseline віддалено або на read-only media.

## Інструменти

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)<sup>[[3]](#references)</sup>
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Посилання

- [1] [File Integrity Monitoring with osquery](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [2] [Tracing Linux: A file integrity monitoring use case (Elastic)](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)
- [3] [Wazuh File Integrity Monitoring (Syscheck and whodata mode)](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

{{#include ../../banners/hacktricks-training.md}}

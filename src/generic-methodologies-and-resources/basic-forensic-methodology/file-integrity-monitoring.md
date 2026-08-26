# Моніторинг цілісності файлів

{{#include ../../banners/hacktricks-training.md}}

## Базова лінія

Базова лінія передбачає створення знімка певних частин системи, щоб **порівнювати його з майбутнім станом і виявляти зміни**.

Наприклад, можна обчислити й зберегти хеш кожного файла файлової системи, щоб визначити, які файли було змінено.\
Так само можна відстежувати створені облікові записи користувачів, запущені процеси, запущені служби та будь-які інші елементи, які не повинні часто або взагалі змінюватися.

**Корисна базова лінія** зазвичай зберігає не лише дайджест: також варто відстежувати дозволи, власника, групу, часові мітки, inode, ціль symlink, ACL і вибрані розширені атрибути.<sup>[[4]](#references)</sup> З погляду пошуку атак це допомагає виявляти **втручання лише в дозволи**, **атомарну заміну файлів** і **закріплення через змінені файли служб/unit**, навіть якщо хеш вмісту не змінюється першим.

### Моніторинг цілісності файлів

Моніторинг цілісності файлів (FIM) — це критично важлива техніка безпеки, яка захищає IT-середовища й дані шляхом відстеження змін у файлах. Зазвичай він поєднує:<sup>[[1]](#references)[[3]](#references)</sup>

1. **Порівняння з базовою лінією:** зберігайте метадані та криптографічні контрольні суми (бажано `SHA-256` або кращі) для майбутніх порівнянь.
2. **Сповіщення в реальному часі:** підписуйтеся на нативні події файлової системи ОС, щоб знати, **який файл змінився, коли саме і, в ідеалі, який процес/користувач до нього звертався**.
3. **Періодичне повторне сканування:** відновлюйте рівень довіри після перезавантажень, втрати подій, збоїв агента або навмисної антифорензичної активності.

Для threat hunting FIM зазвичай корисніший, якщо зосереджений на **шляхах із високою цінністю**, зокрема:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, розташування cron, матеріали SSH, модулі PAM, web roots
- Місця закріплення у Windows, бінарні файли служб, файли запланованих завдань, startup folders
- Доступні для запису шари контейнерів і bind-mounted secrets/configuration

## Бекенди реального часу та сліпі зони

### Linux

Бекенд збору має значення:<sup>[[2]](#references)[[9]](#references)</sup>

- **`inotify` / `fsnotify`**: прості й поширені, але ліміти спостереження можуть бути вичерпані, а деякі крайові випадки пропускаються.
- **`auditd` / audit framework**: кращий варіант, коли потрібно знати, **хто змінив файл** (UID входу, ID процесу та назву процесу).
- **`eBPF` / `kprobes`**: новіші варіанти, які використовуються сучасними FIM-стеками для збагачення подій і зменшення частини операційних проблем звичайних розгортань `inotify`.

Деякі практичні нюанси:<sup>[[1]](#references)[[5]](#references)</sup>

- Якщо програма **замінює** файл за схемою `write temp -> rename`, спостереження безпосередньо за файлом може перестати бути корисним. **Відстежуйте батьківський каталог**, а не лише файл.
- Колектори на основі `inotify` можуть пропускати події або працювати нестабільно у випадку **дуже великих дерев каталогів**, **операцій із hard link** або після **видалення файла, за яким ведеться спостереження**.
- Дуже великі рекурсивні набори спостереження можуть непомітно перестати працювати, якщо значення `fs.inotify.max_user_watches`, `max_user_instances` або `max_queued_events` є недостатніми.
- Для моніторингу на основі `inotify` мережеві файлові системи є сліпою зоною, оскільки про віддалені зміни не повідомляється.

Приклад базової лінії та перевірки за допомогою AIDE:<sup>[[4]](#references)</sup>
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
Якщо вам потрібна **атрибуція процесу**, а не лише зміни на рівні шляхів, надавайте перевагу телеметрії на основі аудиту, наприклад `osquery` `process_file_events` або режиму Wazuh `whodata`.<sup>[[1]](#references)[[3]](#references)[[9]](#references)</sup>

#### `io_uring`: телеметрія syscall — це не FIM

У сучасному Linux відстеження `openat(2)`, `write(2)` або інших точок входу syscall **не еквівалентне моніторингу фактичної операції файлової системи**. У proof of concept **Curing** за 2025 рік запити до файлів і мережі ставилися в чергу через `io_uring`, тому продукти або політики, підключені лише до відповідних записів syscall для окремих операцій, втрачали телеметрію процесів. У тих самих тестах компонент FIM, обмежений певним шляхом, усе ще виявляв модифікації файлів, що показує: це **сліпа зона розміщення hook**, а не обхід дозволів і не спосіб обійти кожен FIM backend.<sup>[[10]](#references)</sup>

Під час перевірки сенсора змінюйте той самий canary кількома способами: звичайний `write`, `mmap` + `msync`, `truncate`, `sendfile`/`copy_file_range`, атомарна заміна та `io_uring`. Перевіряйте не лише виявлення остаточної зміни hash, а й те, чи зберігає подія відповідальний процес, контейнер/cgroup, шлях, видимий у namespace, inode і пару операцій перейменування. Відсутність події в реальному часі з подальшою невідповідністю під час періодичного сканування слід трактувати як **втрату телеметрії**, а не як звичайну незрозумілу зміну.<sup>[[10]](#references)[[11]](#references)</sup>

Для моніторингу на основі eBPF надавайте перевагу поширеним точкам enforcement у kernel замість переліку probes на вході syscall. Наприклад, політика доступу до файлів Tetragon використовує `security_file_permission` для охоплення звичайних операцій I/O, `sendfile`, `copy_file_range`, AIO і `io_uring`; окремо вона охоплює memory mappings через `security_mmap_file`, а зміни розміру — через `security_path_truncate`. Це також демонструє, чому один hook рідко забезпечує повне охоплення.<sup>[[11]](#references)</sup>

### Windows

У Windows FIM є надійнішим, якщо поєднати **журнали змін** із **телеметрією процесів/файлів із високою інформативністю**:<sup>[[6]](#references)[[7]](#references)</sup>

- **NTFS USN Journal** надає постійний журнал змін файлів на рівні тому.
- **Sysmon Event ID 11** корисний для виявлення створення/перезапису файлів.
- **Sysmon Event ID 2** допомагає виявляти **timestomping**.
- **Sysmon Event ID 15** корисний для **іменованих альтернативних потоків даних (ADS)**, таких як `Zone.Identifier` або приховані payload-потоки.

Швидкі приклади USN triage:<sup>[[7]](#references)</sup>
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
Для глибшого розгляду anti-forensic ідей навколо **timestamp manipulation**, **ADS abuse** та **USN tampering** див. [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Контейнери

Container FIM часто не відстежує реальний шлях запису. У Docker `overlay2` файлова система контейнера поєднує доступні лише для читання шари образу `lowerdir` із доступним для запису **верхнім шаром** (`upperdir`/`diff`), а записи у файли образу копіюються до цього верхнього шару.<sup>[[8]](#references)</sup> Тому:

- Моніторинг лише шляхів **усередині** короткоживучого контейнера може не виявити зміни після повторного створення контейнера.
- Моніторинг **шляху на хості**, який відповідає доступному для запису шару, або відповідного bind-mounted volume часто є кориснішим.
- FIM для шарів образу відрізняється від FIM для файлової системи запущеного контейнера.

## Нотатки з полювання, орієнтованого на атакувальників

- Відстежуйте **визначення сервісів** і **планувальники завдань** так само ретельно, як і бінарні файли. Атакувальники часто забезпечують persistence, змінюючи unit-файл, cron-запис або XML завдання, а не модифікуючи `/bin/sshd`.
- Одного хешу вмісту недостатньо. Багато компрометацій спочатку проявляються як **відхилення owner/mode/xattr/ACL**.
- Якщо ви підозрюєте тривале проникнення, використовуйте обидва підходи: **real-time FIM** для виявлення свіжої активності та **порівняння з cold baseline** із довіреного носія.
- Якщо атакувальник отримав root або kernel execution, вважайте FIM-агент і його базу даних ненадійними. Зберігайте логи та baseline віддалено або на носіях, доступних лише для читання, коли це можливо.<sup>[[4]](#references)</sup>

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
- [4] [Посібник AIDE, версія 0.16.2](https://aide.github.io/doc/)
- [5] [Сторінка посібника Linux для inotify(7)](https://man7.org/linux/man-pages/man7/inotify.7.html)
- [6] [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [7] [fsutil usn](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsutil-usn)
- [8] [Драйвер сховища OverlayFS](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/)
- [9] [Розширені налаштування Wazuh FIM](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)
- [10] [io_uring Rootkit обходить Linux Security Tools (ARMO)](https://www.armosec.io/blog/io_uring-rootkit-bypasses-linux-security/)
- [11] [Доступ до імен файлів: синхронні, асинхронні, відображені та шляхи truncation (Tetragon)](https://tetragon.io/docs/use-cases/filename-access/)
{{#include ../../banners/hacktricks-training.md}}

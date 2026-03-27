# File Integrity Monitoring

{{#include ../../banners/hacktricks-training.md}}

## Baseline

Базовий стан (baseline) — це знімок певних частин системи, який потім порівнюють із майбутнім станом, щоб **виділити зміни**.

Наприклад, можна обчислити та зберегти хеш кожного файлу файлової системи, щоб визначити, які файли були змінені.\
Це також можна робити для створених облікових записів користувачів, запущених процесів, служб і будь-чого іншого, що не повинно часто змінюватися або взагалі не змінюватися.

**Корисний baseline** зазвичай зберігає не лише дайджест: також варто відстежувати права доступу, власника, групу, timestamps, inode, symlink target, ACLs та вибрані розширені атрибути. З точки зору huntingu за атакуючими, це допомагає виявляти **маніпуляції лише з правами доступу**, **атомарну заміну файлу** та **персистентність через змінені service/unit файли**, навіть коли хеш вмісту не є першим, що змінюється.

### File Integrity Monitoring

File Integrity Monitoring (FIM) — критична техніка безпеки, яка захищає ІТ-середовища та дані шляхом відстеження змін у файлах. Зазвичай включає:

1. **Baseline comparison:** Зберігати метадані та криптографічні контрольні суми (рекомендується `SHA-256` або кращі) для подальших порівнянь.
2. **Real-time notifications:** Підписуватись на нативні події файлової системи ОС, щоб знати **який файл змінився, коли і бажано який процес/користувач його торкнувся**.
3. **Periodic re-scan:** Перебудовувати довіру після перезавантажень, пропущених подій, відмов агента або умисної антифорової активності.

Для threat hunting FIM зазвичай корисніший, коли зосереджений на **high-value paths**, таких як:

- `/etc`, `/boot`, `/usr/local/bin`, `/usr/local/sbin`
- `systemd` units, cron locations, SSH material, PAM modules, web roots
- Windows persistence locations, service binaries, scheduled task files, startup folders
- Container writable layers and bind-mounted secrets/configuration

## Real-Time Backends & Blind Spots

### Linux

Вибір бекенду збору має значення:

- **`inotify` / `fsnotify`**: просто і поширено, але ліміти спостереження можуть вичерпатись і деякі крайні випадки пропускаються.
- **`auditd` / audit framework**: кращий, коли потрібно знати **хто змінив файл** (`auid`, процес, pid, executable).
- **`eBPF` / `kprobes`**: новіші опції, які використовуються сучасними FIM-стеками для збагачення подій і зменшення деяких операційних проблем звичайних `inotify`-впроваджень.

Декілька практичних підводних каменів:

- Якщо програма **замінює** файл через `write temp -> rename`, спостереження за самим файлом може стати марним. **Спостерігайте за батьківською директорією**, а не лише за файлом.
- Колектори на основі `inotify` можуть пропускати або деградувати на **величезних деревоподібних директоріях**, при активності з hard-link-ами або після того, як **спостережуваний файл видалено**.
- Дуже великі рекурсивні набори спостережень можуть мовчки зірватися, якщо `fs.inotify.max_user_watches`, `max_user_instances` або `max_queued_events` занадто малі.
- Мережеві файлові системи зазвичай погано підходять для низькошумного моніторингу FIM.

Example baseline + verification with AIDE:
```bash
aide --init
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
aide --check
```
Приклад конфігурації `osquery` FIM, орієнтованої на attacker persistence paths:
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
Якщо вам потрібна **process attribution**, а не лише зміни на рівні шляху, віддавайте перевагу аудиторській телеметрії, наприклад `osquery` `process_file_events` або режиму `whodata` у Wazuh.

### Windows

На Windows FIM працює надійніше, коли ви поєднуєте **change journals** з **high-signal process/file telemetry**:

- **NTFS USN Journal** надає постійний журнал змін файлів для кожного тому.
- **Sysmon Event ID 11** корисний для виявлення створення/перезапису файлів.
- **Sysmon Event ID 2** допомагає виявляти **timestomping**.
- **Sysmon Event ID 15** корисний для **named alternate data streams (ADS)**, таких як `Zone.Identifier` або прихованих payload-потоків.

Швидкі приклади триажу USN:
```cmd
fsutil usn queryjournal C:
fsutil usn readjournal C:
fsutil usn readdata C:\Windows\Temp\sample.bin
```
For deeper anti-forensic ideas around **timestamp manipulation**, **ADS abuse**, and **USN tampering**, check [Anti-Forensic Techniques](anti-forensic-techniques.md).

### Контейнери

Container FIM frequently misses the real write path. With Docker `overlay2`, changes are committed into the container's **writable upper layer** (`upperdir`/`diff`), not the read-only image layers. Therefore:

- Моніторинг лише шляхів з **inside** короткоживучого контейнера може пропустити зміни після відтворення контейнера.
- Моніторинг **host path**, що лежить під writable layer або відповідним bind-mounted volume, часто корисніший.
- FIM на image layers відрізняється від FIM на файловій системі запущеного контейнера.

## Нотатки для пошуку, орієнтовані на атакуючого

- Відстежуйте **service definitions** та **task schedulers** так само ретельно, як і бінарні файли. Attackers often get persistence by modifying a unit file, cron entry, or task XML rather than patching `/bin/sshd`.
- Один лише content hash недостатній. Багато компрометацій спочатку проявляються як **owner/mode/xattr/ACL drift**.
- Якщо підозрюєте зрілу компрометацію, робіть обидва: **real-time FIM** для свіжої активності та a **cold baseline comparison** з trusted media.
- Якщо в attacker є root або kernel execution, припускайте, що FIM agent, його база даних і навіть джерело подій можуть бути змінені. Зберігайте logs та baselines віддалено або на read-only media, коли це можливо.

## Інструменти

- [AIDE](https://aide.github.io/)
- [osquery](https://osquery.io/)
- [Wazuh FIM / Syscheck](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)
- [Elastic Auditbeat File Integrity Module](https://www.elastic.co/docs/reference/beats/auditbeat/auditbeat-module-file_integrity)
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

## Посилання

- [https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/](https://osquery.readthedocs.io/en/stable/deployment/file-integrity-monitoring/)
- [https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case](https://www.elastic.co/blog/tracing-linux-file-integrity-monitoring-use-case)

{{#include ../../banners/hacktricks-training.md}}

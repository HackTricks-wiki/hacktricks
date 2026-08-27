# macOS Shell Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## `BASH_ENV`

Bash가 script 또는 `-c` command를 실행하기 위해 non-interactively 시작되면 `BASH_ENV`의 값을 확장하고, 요청된 command를 실행하기 전에 그 결과로 지정된 file을 source합니다. Bash는 이 file을 찾을 때 `PATH`를 사용하지 않습니다. 따라서 attacker가 제어하는 environment variables를 사용해 non-interactive Bash를 실행하는 process가 먼저 읽을 수 있는 shell payload를 실행하도록 만들 수 있습니다.<sup>[[1]](#references)</sup>
```bash
cat >/tmp/bash-startup-hook.sh <<'EOF'
#!/bin/bash
/usr/bin/touch /tmp/bash-env-executed
EOF

BASH_ENV=/tmp/bash-startup-hook.sh /bin/bash -c '/usr/bin/true'
test -e /tmp/bash-env-executed && echo 'BASH_ENV executed'
```
이 hook은 대상이 실제로 Bash를 시작할 때만 실행됩니다. 다른 platform의 `/bin/sh` 또는 shell 없이 command를 실행하는 program은 이를 반드시 준수하지 않습니다. Privileged mode의 Bash는 `BASH_ENV`를 무시합니다. effective 및 real user/group ID가 서로 다르면 Bash는 startup files도 건너뛰고 `-p`가 제공되지 않는 한 effective ID를 재설정합니다. `-p`를 사용하면 privileged mode가 계속 활성화되며 `BASH_ENV`는 여전히 무시됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

macOS에서 `launchd` jobs는 상속된 또는 job별 environment variables를 정의할 수 있으므로, privileged scripts에 환경을 전달하는 plists와 launch contexts를 점검해야 합니다. interpreter variables를 정리하는 데 SIP만 의존하지 마십시오. 최소 환경(`env -i`)을 사용하고, `BASH_ENV`를 명시적으로 unset하며, 의도한 interpreter를 absolute path로 호출하고, writable startup files를 피하십시오.

## zsh `ZDOTDIR`

zsh는 non-interactive shells를 포함한 모든 일반 shell에서 `$ZDOTDIR/.zshenv`를 읽습니다. `ZDOTDIR`이 unset이면 `HOME`을 사용합니다. 따라서 `ZDOTDIR`을 writable directory로 redirect하면 `zsh -c` command 또는 script보다 먼저 해당 디렉터리의 `.zshenv`가 실행됩니다.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/zsh-startup
echo '/usr/bin/touch /tmp/zshenv-executed' > /tmp/zsh-startup/.zshenv
ZDOTDIR=/tmp/zsh-startup /bin/zsh -c /usr/bin/true
```
`zsh -f`는 `RCS` 옵션을 해제하고 이 사용자 startup file을 건너뜁니다. 전역 `/etc/zshenv`는 여전히 읽히므로 신뢰할 수 있고 최소한의 내용으로 유지해야 합니다.

## fish `XDG_CONFIG_HOME`

fish는 interactive 또는 login shell뿐만 아니라 모든 shell의 startup 시점에 `$XDG_CONFIG_HOME/fish/conf.d/*.fish` 및 `$XDG_CONFIG_HOME/fish/config.fish`를 읽습니다. 또한 `XDG_DATA_DIRS`의 항목 아래에 있는 `fish/vendor_conf.d/*.fish`도 실행합니다. 따라서 공격자가 이러한 변수 중 하나와 읽을 수 있는 디렉터리를 제어하면 fish script 또는 `-c` command보다 먼저 code를 실행할 수 있습니다.<sup>[[4]](#references)</sup>
```bash
mkdir -p /tmp/fish-startup/fish
echo 'touch /tmp/fish-config-executed' > /tmp/fish-startup/fish/config.fish
XDG_CONFIG_HOME=/tmp/fish-startup fish -c true

# Vendor configuration variant
mkdir -p /tmp/fish-vendor/fish/vendor_conf.d
echo 'touch /tmp/fish-vendor-executed' > /tmp/fish-vendor/fish/vendor_conf.d/10-hook.fish
XDG_DATA_DIRS=/tmp/fish-vendor fish -c true
```
신뢰할 수 있는 invocation에는 `fish --no-config`를 사용하고, 신뢰할 수 없는 XDG path variables를 clear하세요.

## References

- [1] [Bash Startup Files](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
- [2] [Bash Invoking Bash](https://www.gnu.org/software/bash/manual/html_node/Invoking-Bash.html)
- [3] [zsh Startup/Shutdown Files](https://zsh.sourceforge.io/Doc/Release/Files.html#Startup_002fShutdown-Files)
- [4] [fish Configuration files](https://fishshell.com/docs/current/language.html#configuration-files)
{{#include ../../../banners/hacktricks-training.md}}

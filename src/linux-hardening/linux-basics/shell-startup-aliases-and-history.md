# Shell 시작, 별칭 및 기록

{{#include ../../banners/hacktricks-training.md}}

별칭, 함수, 시작 파일 또는 환경 변수가 실행 방식을 바꾸면 shell 명령은 이름이 같은 실행 파일과 다르게 동작할 수 있습니다. 명령의 출력을 신뢰하거나 스크립트가 대화형 세션과 동일한 PATH를 사용한다고 가정하기 전에 이를 확인하세요.

## 현재 shell 검사하기

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type`과 `command -V`는 이름이 alias, function, builtin 또는 파일 중 무엇으로 해석되는지 보여 줍니다. `command -v`와 `which`는 alias와 function에 대해 같은 결과를 보여 주지 않을 수 있습니다. Shell history에는 명령이나 자격 증명이 노출될 수 있지만, 기록이 불완전하거나 비활성화되어 있을 수 있으며 세션이 종료될 때까지 메모리에만 저장될 수도 있습니다.

## 시작 및 history 파일 검토

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

사용자가 쓸 수 있는 startup 파일은 이후 shell 실행 시 명령을 실행할 수 있습니다. 하위 권한 계정이 시스템 전체 startup 파일이나 권한이 높은 사용자의 startup 파일을 수정할 수 있다면, 해당 파일은 더 민감합니다. 비대화형 Bash도 `BASH_ENV`에 지정된 파일을 읽을 수 있습니다. [environment variables](linux-environment-variables.md#bash_env--env) 페이지에서 이 동작과 다른 interpreter hook을 설명합니다. persistence 경로라고 주장하기 전에 실제 shell이 로그인, 대화형, 비대화형 세션에서 어떤 파일을 읽는지 확인하세요.

전역 startup 파일에서 source하는 파일도 검사하세요. 예를 들어 `/etc/bash.bashrc`에 `source /opt/app/venv/bin/activate`가 그대로 있으면, shell이 해당 startup 파일을 실제로 읽을 때 activation 파일을 shell 코드로 실행합니다. activation 파일, 심볼릭 링크 및 상위 디렉터리의 권한, ACL을 확인하세요. 하위 권한 사용자가 파일을 쓸 수 있더라도, 권한이 높은 shell이나 권한 있는 작업이 나중에 해당 파일을 source해야 영향을 줄 수 있습니다. 쓰기 권한이 `sudoedit`에 달려 있다면, 먼저 정확한 sudoers 규칙과 설치된 공급업체 패치 버전의 sudo 패키지를 확인하세요. upstream 버전 문자열만으로는 [sudoedit argument-injection 노출 여부](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)를 입증할 수 없습니다.

[users and sessions](../user-information/user-and-session-triage.md)에 설명된 대로 history, dotfile, 백업에서 secret을 확인하세요. 권한이 높은 스크립트가 이름으로 명령을 찾는다면, 이 검토를 [PATH hijacking 안내](linux-environment-variables.md#path)와 함께 진행하세요.

## Zsh startup 리디렉션 및 컴파일 파일

기본 `RCS` 설정에서 zsh는 일반적인 실행뿐 아니라 `zsh -c`와 스크립트를 실행할 때도 먼저 `$ZDOTDIR/.zshenv`를 읽습니다. `ZDOTDIR`이 설정되지 않았으면 `$HOME`을 사용합니다. 명령 실행기가 환경 변수 맵을 받는 경우, 권한이 높은 zsh 프로세스에 두 변수 중 하나를 전달하는지 테스트하세요. 그러면 쓰기 가능한 `.zshenv`가 실행기에서 검사하거나 allowlist에 넣은 명령 본문보다 **먼저** 실행되거나, 명령 본문을 우회할 수 있습니다. 이를 위해서는 권한이 높은 프로세스가 리디렉션된 디렉터리를 상속해야 합니다. `zsh -f`는 사용자 startup 파일은 건너뛰지만 전역 `zshenv`는 건너뛰지 않습니다. 전역 파일은 대개 `/etc/zshenv`이지만 배포판마다 경로가 다릅니다. [macOS zsh injection 페이지](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir)에 간단한 `ZDOTDIR` 예제가 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

최신의 유효한 `.zshenv.zwc` 또는 `.zshrc.zwc`가 있으면, plaintext startup 파일 대신 해당 파일이 실행됩니다. startup 디렉터리에 쓸 수 있다면 파일을 수정해 컴파일한 다음, 무해해 보이는 plaintext 파일로 되돌려 컴파일된 복사본에 실행 코드를 남길 수 있습니다. 이는 난독화일 뿐 암호화가 아닙니다. 아래의 일회용 테스트는 텍스트 파일만 검사해서는 왜 충분하지 않은지 보여줍니다. 실제 home 디렉터리는 건드리지 않습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

```bash
lab=$(mktemp -d)
printf '%s\n' 'print -r -- compiled > "$ZDOTDIR/result"' > "$lab/.zshenv"
zsh -f -c 'zcompile -R "$1"' _ "$lab/.zshenv"
printf '%s\n' 'print -r -- plaintext > "$ZDOTDIR/result"' > "$lab/.zshenv"
touch -d '2 minutes ago' "$lab/.zshenv"  # ensure the .zwc is newer
ZDOTDIR="$lab" zsh -c :
cat "$lab/result"  # compiled
zsh -f -c 'zcompile -t "$1"' _ "$lab/.zshenv.zwc"
```

실제 대상의 경우 유효한 `ZDOTDIR`/`HOME`을 확인하고, 텍스트 파일과 `.zwc` 파일을 모두 검사해 타임스탬프, 소유권, 쓰기 가능한 상위 디렉터리를 확인하세요. `.zwc` 파일이 우선 적용되려면 원본 파일과 일치하고 원본보다 최신이어야 합니다.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh 시작 및 종료 파일](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell 시작 환경 주입 권고](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh 셸 내장 명령: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [확인하는 것을 잊은 .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
{{#include ../../banners/hacktricks-training.md}}

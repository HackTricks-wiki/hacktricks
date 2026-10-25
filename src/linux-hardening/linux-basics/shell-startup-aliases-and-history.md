# Shell 시작, Alias 및 History

{{#include ../../banners/hacktricks-training.md}}

Alias, function, startup file 또는 environment variable에 의해 실행 방식이 바뀌면 shell command는 같은 이름의 executable과 다르게 동작할 수 있습니다. command의 출력을 신뢰하거나 script가 interactive session과 같은 PATH를 사용한다고 가정하기 전에 이를 확인하세요.

## 현재 shell 검사하기

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type`과 `command -V`는 이름이 alias, function, builtin 또는 파일 중 무엇으로 해석되는지 보여 줍니다. `command -v`와 `which`는 alias와 function에 대해 서로 다른 결과를 보여 줄 수 있습니다. Shell history에는 명령어나 자격 증명이 노출될 수 있지만, 기록이 불완전하거나 비활성화되어 있거나 세션이 종료될 때까지 메모리에만 저장되어 있을 수 있습니다.

수정된 `.bashrc`는 암호 입력 프롬프트를 흉내 내고, 입력값을 기록한 뒤 실제 명령어에 전달하는 `sudo` alias를 정의할 수 있습니다. 이렇게 하면 `sudo` 실행 파일이나 `PATH`를 변경하지 않고도 자격 증명 가로채기를 숨길 수 있습니다.<sup>[[5]](#references)</sup> Shell은 수정된 시작 파일을 읽고 alias를 확장해야 합니다.<sup>[[7]](#references)</sup> 기본적으로 비대화형 Bash는 `expand_aliases`가 활성화되어 있지 않으면 alias를 확장하지 않습니다.<sup>[[6]](#references)</sup>

## 시작 파일 및 history 파일 검토하기

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

사용자가 쓸 수 있는 startup 파일은 다음번 셸 실행 시 명령을 실행할 수 있습니다. 낮은 권한의 계정이 시스템 전체 startup 파일이나 권한이 높은 사용자의 startup 파일을 수정할 수 있다면, 해당 파일은 더 민감합니다. 비대화형 Bash도 `BASH_ENV`에 지정된 파일을 읽을 수 있습니다. [환경 변수](linux-environment-variables.md#bash_env--env) 페이지에서 이러한 동작과 다른 인터프리터 후크를 설명합니다. persistence 경로라고 단정하기 전에 실제 셸이 로그인, 대화형, 비대화형 세션에서 어떤 파일을 읽는지 확인하세요.

전역 startup 파일이 source하는 파일도 살펴보세요. 예를 들어 `/etc/bash.bashrc`에 `source /opt/app/venv/bin/activate`가 그대로 들어 있으면, 셸이 실제로 해당 startup 파일을 읽을 때 activation 파일을 셸 코드로 실행합니다. activation 파일, 심볼릭 링크와 상위 디렉터리의 권한, ACL을 검토하세요. 낮은 권한의 사용자가 파일을 쓸 수 있어도, 권한이 높은 셸이나 권한이 높은 작업이 나중에 해당 파일을 source해야만 그 셸에 영향을 줄 수 있습니다. 쓰기 권한이 `sudoedit`에 달려 있다면, 먼저 정확한 sudoers 규칙과 설치된 공급업체 패치 버전의 sudo 패키지를 확인하세요. upstream 버전 문자열만으로는 [sudoedit 인자 주입 취약점 노출](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)을 입증할 수 없습니다.

[사용자와 세션](../user-information/user-and-session-triage.md)에 설명된 대로 history, dotfiles, 백업에서 비밀 정보를 확인하세요. 권한이 높은 스크립트가 이름으로 명령을 찾는다면, 이 검토와 [PATH hijacking 지침](linux-environment-variables.md#path)을 함께 적용하세요.

## Zsh startup 리디렉션 및 컴파일된 파일

기본 `RCS` 설정에서 zsh는 일반적인 실행 전에 `$ZDOTDIR/.zshenv`를 읽습니다. 여기에는 `zsh -c`와 스크립트도 포함됩니다. `ZDOTDIR`이 설정되지 않았다면 `$HOME`을 사용합니다. 명령 실행기가 환경 맵을 받는 경우, 이 변수를 권한이 높은 zsh 프로세스에 전달하는지 확인하세요. 그러면 쓰기 가능한 `.zshenv`가 실행기가 검사하거나 허용 목록에 등록한 명령 본문보다 먼저 실행될 수 있습니다. 이 동작이 발생하려면 권한이 높은 프로세스가 리디렉션된 디렉터리를 상속해야 합니다. `zsh -f`는 사용자 startup 파일은 건너뛰지만 전역 `zshenv`(일반적으로 `/etc/zshenv`이지만 배포판에 따라 경로가 다름)는 건너뛰지 않습니다. [macOS zsh injection 페이지](../../macos-hardening/macos-security-and-privilege-escalation/macos-proces-abuse/macos-bash-applications-injection.md#zsh-zdotdir)에 간단한 `ZDOTDIR` 예제가 있습니다.<sup>[[1]](#references)[[2]](#references)</sup>

더 새롭고 유효한 `.zshenv.zwc` 또는 `.zshrc.zwc`가 있으면 일반 텍스트 startup 파일 대신 해당 파일이 실행됩니다. startup 디렉터리에 쓸 수 있다면, 수정한 파일을 컴파일한 다음 겉보기에 무해한 일반 텍스트 파일로 복원해 컴파일된 사본에 실행 코드를 남길 수 있습니다. 이는 암호화가 아니라 은폐입니다. 아래의 일회용 테스트는 텍스트 파일만 검사하는 것이 왜 충분하지 않은지 보여줍니다. 실제 home 디렉터리에는 영향을 주지 않습니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>

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

실제 대상에서는 유효한 `ZDOTDIR`/`HOME`을 확인하고, 텍스트 파일과 `.zwc` 파일을 모두 살펴보며, 타임스탬프, 소유권, 쓰기 가능한 상위 디렉터리를 확인하세요. `.zwc` 파일이 우선 적용되려면 원본 파일과 일치하고 원본보다 최신이어야 합니다.<sup>[[1]](#references)[[3]](#references)</sup>



## References

- [1] [Zsh 시작 및 종료 파일](https://zsh.sourceforge.io/Doc/Release/Files.html)
- [2] [Shell 시작 환경 주입 보안 권고](https://github.com/openclaw/openclaw/security/advisories/GHSA-xgf2-vxv2-rrmg)
- [3] [Zsh 셸 내장 명령: zcompile](https://zsh.sourceforge.io/Doc/Release/Shell-Builtin-Commands.html)
- [4] [확인을 놓친 .zshrc.zwc](https://dfir.ch/posts/compiled_zsh/)
- [5] [AI 기반 스파이 활동 캠페인, 정부 Linux 인프라를 표적으로 삼아](https://unit42.paloaltonetworks.com/ai-campaign-targets-linux-infrastructure/)
- [6] [Bash 매뉴얼: 별칭](https://www.gnu.org/software/bash/manual/html_node/Aliases.html)
- [7] [Bash 매뉴얼: Bash 시작 파일](https://www.gnu.org/software/bash/manual/html_node/Bash-Startup-Files)
{{#include ../../banners/hacktricks-training.md}}

# Shell 시작, 별칭 및 기록

{{#include ../../banners/hacktricks-training.md}}

별칭, 함수, 시작 파일 또는 환경 변수가 실행 방식을 바꾸면, Shell 명령은 이름이 같은 실행 파일과 다르게 동작할 수 있습니다. 명령의 출력을 신뢰하거나 스크립트가 대화형 세션과 동일한 PATH를 사용한다고 가정하기 전에 이러한 요소를 확인하세요.

## 현재 Shell 검사하기

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` 및 `command -V`를 사용하면 이름이 alias, function, builtin 또는 파일 중 무엇으로 확인되는지 알 수 있습니다. `command -v`와 `which`는 alias와 function에 대해 서로 다른 결과를 보여줄 수 있습니다. Shell history에는 명령어나 credentials가 노출될 수 있지만, 기록이 불완전하거나 비활성화되어 있을 수 있으며 세션이 종료될 때까지 메모리에만 보관될 수도 있습니다.

## 시작 파일과 history 파일 검토

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

사용자가 쓸 수 있는 startup 파일은 이후 셸이 실행될 때 명령을 실행할 수 있습니다. 권한이 낮은 계정이 시스템 전체 startup 파일이나 권한이 높은 사용자의 startup 파일을 수정할 수 있다면, 해당 파일은 더 민감합니다. 비대화형 Bash도 `BASH_ENV`에 지정된 파일을 읽을 수 있습니다. [환경 변수](linux-environment-variables.md#bash_env--env) 페이지에서 이 동작과 다른 인터프리터 후크를 설명합니다. persistence 경로라고 단정하기 전에 로그인, 대화형 및 비대화형 세션에서 실제 셸이 어떤 파일을 읽는지 확인하세요.

전역 startup 파일이 불러오는 파일도 살펴보세요. 예를 들어 `/etc/bash.bashrc`에 `source /opt/app/venv/bin/activate`가 문자 그대로 있으면, 셸이 실제로 해당 startup 파일을 읽을 때 activation 파일을 셸 코드로 실행합니다. activation 파일, 심볼릭 링크와 상위 디렉터리 권한, ACL을 검토하세요. 권한이 낮은 사용자가 파일을 수정해도 셸이나 권한이 높은 작업이 나중에 해당 파일을 불러오지 않는다면 권한이 높은 셸에 영향을 줄 수 없습니다. 쓰기 권한이 `sudoedit`에 따라 달라진다면, 먼저 정확한 sudoers 규칙과 설치된 벤더 패치 버전의 sudo 패키지를 확인하세요. upstream 버전 문자열만으로는 [sudoedit 인자 주입 취약점 노출 여부](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)를 판단할 수 없습니다.

[사용자와 세션](../user-information/user-and-session-triage.md)에 설명된 대로 history, dotfile 및 백업에서 비밀 정보를 확인하세요. 권한이 높은 스크립트가 이름으로 명령을 찾는다면, 이 검토를 [PATH 하이재킹 가이드](linux-environment-variables.md#path)와 함께 진행하세요.
{{#include ../../banners/hacktricks-training.md}}

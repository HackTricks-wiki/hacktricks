# 셸 시작, 별칭 및 기록

{{#include ../../banners/hacktricks-training.md}}

별칭, 함수, 시작 파일 또는 환경 변수가 실행 방식을 바꾸면 셸 명령은 같은 이름의 실행 파일과 다르게 동작할 수 있습니다. 명령의 출력을 신뢰하거나 스크립트가 대화형 세션과 같은 PATH를 사용한다고 가정하기 전에 이러한 요소를 확인하세요.

## 현재 셸 확인

```bash
printf '%s\n' "$SHELL" "$PATH"
type -a ls sudo curl 2>/dev/null
alias
command -V python3
history | tail -50
```

`type` 및 `command -V`를 사용하면 이름이 alias, function, builtin 또는 파일로 해석되는지 확인할 수 있습니다. `command -v`와 `which`는 alias와 function에 대해 서로 다른 결과를 보여줄 수 있습니다. 쉘 히스토리에는 명령어나 자격 증명이 노출될 수 있지만, 기록이 불완전하거나 비활성화되어 있거나 세션이 종료될 때까지 메모리에만 저장될 수 있습니다.

## 시작 및 히스토리 파일 검토

```bash
ls -la ~/.bashrc ~/.bash_profile ~/.profile ~/.zshrc ~/.zprofile ~/.bash_history ~/.zsh_history 2>/dev/null
ls -ld /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null
printenv HISTFILE HISTSIZE HISTCONTROL BASH_ENV ENV 2>/dev/null
```

사용자가 쓸 수 있는 startup file은 이후 shell이 실행될 때 명령을 실행할 수 있습니다. 낮은 권한의 계정이 시스템 전체 startup file 또는 권한이 높은 사용자의 startup file을 수정할 수 있다면, 해당 파일은 더 민감합니다. 비대화형 Bash는 `BASH_ENV`로 지정된 파일도 읽을 수 있습니다. [환경 변수](linux-environment-variables.md#bash_env--env) 페이지에서 이 동작과 다른 인터프리터 후크를 설명합니다. persistence 경로라고 단정하기 전에 실제 shell이 로그인, 대화형, 비대화형 세션에서 어떤 파일을 읽는지 확인하세요.

전역 startup file이 source하는 파일도 검사하세요. 예를 들어 `/etc/bash.bashrc`에 `source /opt/app/venv/bin/activate`가 그대로 들어 있다면, shell이 해당 startup file을 실제로 읽을 때 activation file을 shell 코드로 실행합니다. activation file, 심볼릭 링크와 상위 디렉터리의 권한, ACL을 검토하세요. 낮은 권한의 사용자가 쓸 수 있는 파일을 권한이 높은 shell 또는 작업이 나중에 source해야만 해당 사용자가 그 shell에 영향을 줄 수 있습니다. 쓰기 권한이 `sudoedit`에 달려 있다면 먼저 정확한 sudoers 규칙과 설치된 공급업체 패치 버전의 sudo 패키지를 확인하세요. 업스트림 버전 문자열만으로는 [sudoedit 인자 주입 취약성](../main-system-information/linux-privilege-escalation-checklist.md#sudo-and-suid-commands)이 있다고 단정할 수 없습니다.

[사용자 및 세션](../user-information/user-and-session-triage.md)에 설명된 대로 history, dotfiles, 백업에서 비밀 정보를 확인하세요. 권한이 높은 스크립트가 이름으로 명령을 찾는다면 이 검토와 [PATH 하이재킹 지침](linux-environment-variables.md#path)을 함께 적용하세요.
{{#include ../../banners/hacktricks-training.md}}

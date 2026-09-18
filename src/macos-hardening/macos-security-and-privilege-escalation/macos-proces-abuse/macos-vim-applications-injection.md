# Injection dans les applications Vim/Neovim sur macOS

{{#include ../../../banners/hacktricks-training.md}}

## Présentation

Le propre langage de scripting de Vim (Vimscript) peut exécuter des **commandes Ex et des commandes shell arbitraires au démarrage** à partir de variables d’environnement. Si un processus plus privilégié (un workflow de maintenance/root, un `sudo vim …`, un éditeur lancé par un autre outil, `crontab -e`, `visudo`, `git`/`less` invoquant un éditeur, …) lance Vim/Neovim avec un environnement contrôlé par l’attaquant, celui-ci obtient une exécution de code dans ce contexte.

## `VIMINIT`

Lors de son initialisation, Vim lit et exécute les commandes Ex présentes dans **`VIMINIT`**. Les commandes Ex incluent `:!cmd` (exécuter une commande shell) et `:call system(...)`, de sorte qu’une seule variable permet une exécution arbitraire avant même qu’un fichier ne soit modifié.<sup>[[1]](#references)</sup>
```bash
echo "hi" > /tmp/victim.txt

# Shell command via Ex ':!'
printf ':qa!\n' | VIMINIT='silent! !touch /tmp/vim-executed' vim /tmp/victim.txt
ls -la /tmp/vim-executed

# Pure Vimscript (no external process, e.g. write a file)
printf ':qa!\n' | VIMINIT='call writefile(["x"],"/tmp/vim-vimscript")' vim /tmp/victim.txt
```
La commande `:qa!` fournie via stdin ferme simplement l’éditeur après l’exécution du payload ; dans un scénario réel, la victime ouvre simplement Vim normalement.

## `EXINIT`

Si `VIMINIT` n’est pas défini, Vim (ainsi que les binaires de compatibilité `vi`/`ex`) utilise **`EXINIT`** en secours, lequel est exécuté de la même manière. Il s’agit de la variante classique, datant de l’ère de vi, du même mécanisme.<sup>[[1]](#references)</sup>
```bash
printf ':qa!\n' | EXINIT='silent! !touch /tmp/exinit-executed' vim /tmp/victim.txt
ls -la /tmp/exinit-executed
```
## Notes et réserves

- **Neovim** prend également en charge `VIMINIT` (il est vérifié avant le fichier utilisateur `init.vim`/`init.lua`).
- Le mode Batch/Ex (`vim -es` / `vim -Es`) ne source pas `VIMINIT`/`EXINIT` ; les variables sont exécutées lors d'un démarrage normal (interactif), ce qui correspond au scénario courant pour une victime.
- Les vecteurs associés basés sur des fichiers sont les fonctionnalités `exrc`/`.nvimrc` « modeline »/local-rc par répertoire et `-u <vimrc>` ; le chemin passant par les variables d'environnement ci-dessus ne nécessite aucun fichier accessible en écriture.

## Hardening

- Nettoyez l'environnement (supprimez `VIMINIT`/`EXINIT`) avant de lancer des éditeurs depuis des contextes privilégiés ou automatisés, et préférez des wrappers `sudo -i`/`env -i` qui réinitialisent l'environnement.
- Définissez `EDITOR`/`VISUAL` avec des chemins absolus de confiance et évitez d'exécuter des éditeurs en tant que root avec un environnement utilisateur hérité.
- Considérez le contrôle de l'environnement d'une cible comme équivalent à une exécution de code pour tout Vim/Neovim qu'elle lance.

## References

- [1] [Documentation de Vim — `starting.txt` (initialisation, `VIMINIT`, `EXINIT`)](https://vimhelp.org/starting.txt.html#initialization)
{{#include ../../../banners/hacktricks-training.md}}

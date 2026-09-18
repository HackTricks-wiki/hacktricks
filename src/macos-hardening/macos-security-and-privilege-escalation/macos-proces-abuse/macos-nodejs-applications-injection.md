# Injection d'applications Node.js

{{#include ../../../banners/hacktricks-training.md}}

## Vue d'ensemble

Si un attaquant peut contrôler l'environnement d'un processus qui finit par lancer **Node.js** (le binaire `node` directement, ou tout CLI basé sur Node comme `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), plusieurs variables d'environnement permettent au runtime de **charger et d'exécuter du JavaScript contrôlé par l'attaquant avant le lancement du programme cible**. Il s'agit d'une primitive d'exécution de code équivalente aux familles `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` pour d'autres runtimes.

Le code préchargé s'exécute **dans le même processus**, avec le même uid, le même environnement, les mêmes descripteurs de fichiers et les mêmes entitlements que la victime. Il constitue donc un vecteur propre d'injection/priv-esc lorsqu'un processus plus privilégié lance Node avec un environnement hérité ou influencé par l'attaquant.

## `NODE_OPTIONS` — `--require` (basé sur un fichier)

`NODE_OPTIONS` est analysée comme si son contenu correspondait à des options supplémentaires de la ligne de commande. `--require` (`-r`) précharge un module CommonJS **avant** le point d'entrée, de sorte que son code de niveau supérieur s'exécute en premier.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` avec une URL `data:` (sans fichier)

Depuis **Node 20.6**, `--import` accepte une URL `data:text/javascript,<code>`, ce qui permet de précharger du JavaScript de module ES **inline, sans fichier sur le disque ni répertoire de modules**. Le code doit être **entièrement encodé dans l'URL** (un espace brut ou `#` tronque l'URL de données et produit une `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Voici la technique exploitée dans le cloud, par exemple en injectant `NODE_OPTIONS` dans la configuration d’une fonction AWS Lambda (`lambda:UpdateFunctionConfiguration`, sans `iam:PassRole` requis) afin d’exécuter du code avec le rôle d’exécution.

> [!TIP]
> `NODE_OPTIONS` **ne peut pas exécuter directement du code** : les flags comme `--eval`/`-e`, `-p` ou un chemin de script sont explicitement rejetés (`node: --eval is not allowed in NODE_OPTIONS`). Utilisez `--require`/`--import` pour pointer vers du code à la place.

## `NODE_OPTIONS` — custom loaders / autres flags de démarrage

`NODE_OPTIONS` prend également en charge d’autres flags qui affectent le démarrage et dont l’effet secondaire consiste à exécuter le code de l’attaquant, par exemple un hook de loader ESM :
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Tout launcher basé sur Node qui lance un processus enfant `node` **propage généralement `NODE_OPTIONS`**, ce qui permet à une injection unique d'affecter toute une toolchain (`npm run …`, `npx`, outils de build, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Lorsque Node démarre un **REPL interactif**, il charge le module indiqué par `NODE_REPL_EXTERNAL_MODULE` et exécute son code de niveau supérieur. Cela est utile lorsque la victime lance un shell interactif `node`/`node -i` (outils de développement, consoles de maintenance).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` est intentionnellement **ignoré** lorsque la protection [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) est utilisée pour lancer un processus enfant, mais un REPL interactif lancé directement le prend en compte.

## Electron (`ELECTRON_RUN_AS_NODE`)

Les applications Electron réexposent l'environnement Node complet lorsqu'elles sont démarrées avec **`ELECTRON_RUN_AS_NODE=1`**, auquel cas tous les vecteurs `NODE_OPTIONS` ci-dessus s'appliquent au binaire Electron (souvent signé et doté d'entitlements). Voir :

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Autres runtimes JS

- **Bun** lit `NODE_OPTIONS` pour assurer la compatibilité et prend en charge son propre `--preload` (configurable via `bunfig.toml`).
- **Deno** ne respecte pas `NODE_OPTIONS` ; il nécessite à la place des flags explicites (`--import`, `--preload`) et n'est donc pas vulnérable à un `NODE_OPTIONS` hérité.

Vérifiez toujours le runtime et la version exacts, car les flags acceptés changent selon les versions.

## Renforcement

- Supprimez `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` et `ELECTRON_RUN_AS_NODE` de l'environnement avant de lancer Node depuis un contexte plus privilégié ; lancez les processus enfants avec un environnement nettoyé.
- Considérez la possibilité de définir l'environnement d'une cible (injection de configuration, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, variables CI, configuration Lambda/container) comme équivalente à une exécution de code dans tout processus Node qu'elle lance.
- Surveillez l'exécution des processus pour détecter ces variables, de la même manière que [Shield](https://github.com/theevilbit/Shield) génère des alertes pour `ELECTRON_RUN_AS_NODE` et les variables d'injection dyld.

## References

- [1] [Documentation CLI de Node.js — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [ESM de Node.js — `--import` et URL `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [REPL de Node.js — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

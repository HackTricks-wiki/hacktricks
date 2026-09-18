# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## अवलोकन

यदि कोई attacker ऐसे process के environment को नियंत्रित कर सकता है जो अंततः **Node.js** (`node` binary directly, या कोई भी Node-based CLI जैसे `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …) launch करता है, तो कई environment variables runtime को target program के चलने से **पहले attacker-controlled JavaScript load और execute** करने देते हैं। यह अन्य runtimes के लिए `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` families के समान code-execution primitive है।

Preloaded code **उसी process** में victim के समान uid, environment, file descriptors और entitlements के साथ चलता है, इसलिए जब कोई अधिक privileged process inherited या attacker-influenced environment के साथ Node spawn करता है, तो यह एक स्पष्ट injection/priv-esc vector होता है।

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` को ऐसे parse किया जाता है जैसे इसकी content अतिरिक्त command-line flags हो। `--require` (`-r`) entry point से **पहले** एक CommonJS module preload करता है, इसलिए उसका top-level code सबसे पहले चलता है।<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `data:` URL के साथ `--import` (बिना फ़ाइल के)

**Node 20.6** से `--import` `data:text/javascript,<code>` URL स्वीकार करता है, जिससे आप ES-module JavaScript को **inline रूप में preload** कर सकते हैं, बिना disk पर कोई फ़ाइल और बिना किसी module directory के। Code को **पूरी तरह URL-encoded** होना चाहिए (कोई raw space या `#` data URL को truncate कर देता है और `SyntaxError` उत्पन्न करता है)।<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
यह cloud में abuse की जाने वाली technique है, जैसे AWS Lambda function के configuration में `NODE_OPTIONS` inject करना (`lambda:UpdateFunctionConfiguration`, `iam:PassRole` की आवश्यकता नहीं) ताकि execution role के रूप में code चलाया जा सके।

> [!TIP]
> `NODE_OPTIONS` सीधे code नहीं चला सकता: `--eval`/`-e`, `-p` या script path जैसे flags स्पष्ट रूप से reject किए जाते हैं (`node: --eval is not allowed in NODE_OPTIONS`). इसके बजाय code की ओर point करने के लिए `--require`/`--import` का उपयोग करें।

## `NODE_OPTIONS` — custom loaders / अन्य startup flags

`NODE_OPTIONS` अन्य startup-affecting flags को भी support करता है, जिनका side effect attacker code चलाना होता है, उदाहरण के लिए ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
कोई भी Node-based launcher जो child `node` को spawn करता है, आमतौर पर **`NODE_OPTIONS` को propagate करता है**, इसलिए इसे एक बार inject करने से पूरी toolchain (`npm run …`, `npx`, build tools, test runners, language servers) प्रभावित हो सकती है।

## `NODE_REPL_EXTERNAL_MODULE`

जब Node एक **interactive REPL** शुरू करता है, तो यह `NODE_REPL_EXTERNAL_MODULE` द्वारा निर्दिष्ट module को load करके उसका top-level code execute करता है। यह तब उपयोगी है जब victim एक interactive `node`/`node -i` shell (dev tooling, maintenance consoles) launch करता है।<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` को जानबूझकर **ignored** किया जाता है जब `kDisableNodeOptionsEnv` protection का उपयोग करके child को spawn किया जाता है, लेकिन सीधे launch किया गया interactive REPL इसे honour करता है।

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron applications **`ELECTRON_RUN_AS_NODE=1`** के साथ शुरू किए जाने पर full Node runtime को फिर से expose करती हैं। उस समय ऊपर दिए गए सभी `NODE_OPTIONS` vectors (अक्सर signed/entitled) Electron binary पर लागू होते हैं। देखें:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## अन्य JS runtimes

- **Bun** compatibility के लिए `NODE_OPTIONS` पढ़ता है और अपना `--preload` support करता है (`bunfig.toml` के माध्यम से configurable)।
- **Deno** `NODE_OPTIONS` को honour नहीं करता; इसके बजाय explicit flags (`--import`, `--preload`) आवश्यक होते हैं, इसलिए inherited `NODE_OPTIONS` के प्रति vulnerable नहीं है।

हमेशा exact runtime और version की पुष्टि करें, क्योंकि accepted flags releases के बीच बदलते रहते हैं।

## Hardening

- अधिक privileged context से Node launch करने से पहले environment से `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` और `ELECTRON_RUN_AS_NODE` हटाएँ; children को sanitized environment के साथ spawn करें।
- किसी target का environment सेट करने की ability (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config) को उसके द्वारा launch की जाने वाली किसी भी Node process में code execution के equivalent मानें।
- इन variables के लिए process exec को उसी तरह monitor करें, जैसे [Shield](https://github.com/theevilbit/Shield) `ELECTRON_RUN_AS_NODE` और dyld injection variables पर alert करता है।

## References

- [1] [Node.js CLI documentation — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` और `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Genel Bakış

Bir attacker, sonunda **Node.js** çalıştıran bir process'in environment'ını kontrol edebiliyorsa (`node` binary'si doğrudan veya `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next` gibi Node tabanlı herhangi bir CLI), çeşitli environment variable'lar runtime'ın target program çalışmadan önce attacker-controlled JavaScript yükleyip execute etmesini sağlar. Bu, diğer runtime'lar için kullanılan `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` ailelerine eşdeğer bir code-execution primitive'idir.

Preloaded code, victim ile **aynı process** içinde ve victim ile aynı uid, environment, file descriptor'lar ve entitlement'lar kullanılarak çalışır. Bu nedenle daha privileged bir process, inherited veya attacker-influenced bir environment ile Node'u başlattığında temiz bir injection/priv-esc vector'ü oluşturur.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS`, içeriği ek command-line flag'leriymiş gibi parse edilir. `--require` (`-r`), entry point'ten **önce** bir CommonJS module'ünü preload eder; böylece top-level code önce çalışır.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `data:` URL ile `--import` (filesiz)

**Node 20.6** sürümünden itibaren `--import`, bir `data:text/javascript,<code>` URL'sini kabul eder ve ES-module JavaScript kodunu **diskte dosya veya module directory olmadan, satır içinde** önceden yüklemenizi sağlar. Kod **tamamen URL-encoded** olmalıdır (ham bir boşluk veya `#`, data URL'sini keser ve `SyntaxError` üretir).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Bu, cloud ortamında abuse edilen tekniktir; örneğin bir AWS Lambda function yapılandırmasına (`lambda:UpdateFunctionConfiguration`, `iam:PassRole` gerekmez) `NODE_OPTIONS` inject ederek execution role olarak code çalıştırmak.

> [!TIP]
> `NODE_OPTIONS` doğrudan code çalıştıramaz: `--eval`/`-e`, `-p` veya bir script path gibi flag'ler açıkça reddedilir (`node: --eval is not allowed in NODE_OPTIONS`). Bunun yerine code'a işaret etmek için `--require`/`--import` kullanın.

## `NODE_OPTIONS` — custom loader'lar / diğer startup flag'leri

`NODE_OPTIONS`, attacker code çalıştırma yan etkisine sahip diğer startup-affecting flag'leri de destekler; örneğin bir ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Node tabanlı bir child `node` başlatan herhangi bir launcher genellikle **`NODE_OPTIONS`'ı aktarır**; bu nedenle bir kez inject edilmesi, tüm bir toolchain'i (`npm run …`, `npx`, build tools, test runners, language servers) etkileyebilir.

## `NODE_REPL_EXTERNAL_MODULE`

Node bir **interactive REPL** başlattığında, `NODE_REPL_EXTERNAL_MODULE` tarafından belirtilen module'ü yükler ve module'ün top-level code'unu çalıştırır. Bu, hedef interactive bir `node`/`node -i` shell'i (dev tooling, maintenance consoles) başlattığında kullanışlıdır.<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE`, bir child spawn etmek için `kDisableNodeOptionsEnv` protection kullanıldığında kasıtlı olarak **yok sayılır**, ancak doğrudan başlatılan etkileşimli bir REPL bunu dikkate alır.

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron applications, **`ELECTRON_RUN_AS_NODE=1`** ile başlatıldığında full Node runtime'ını yeniden açığa çıkarır; bu noktada yukarıdaki tüm `NODE_OPTIONS` vektörleri (çoğunlukla signed/entitled olan) Electron binary'sine uygulanır. Bkz.:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Diğer JS runtimes

- **Bun**, compatibility için `NODE_OPTIONS` okur ve kendi `--preload` seçeneğini destekler (`bunfig.toml` üzerinden yapılandırılabilir).
- **Deno**, `NODE_OPTIONS` değerini dikkate almaz; bunun yerine açıkça belirtilen flag'leri (`--import`, `--preload`) gerektirir. Bu nedenle, miras alınan bir `NODE_OPTIONS` değerine karşı vulnerable değildir.

Kabul edilen flag'ler release'ler arasında değiştiğinden, her zaman kullanılan runtime'ı ve version'ı doğrulayın.

## Hardening

- Daha privileged bir context'ten Node başlatmadan önce `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` ve `ELECTRON_RUN_AS_NODE` değerlerini environment'tan kaldırın; child process'leri sanitized bir environment ile spawn edin.
- Bir target'ın environment'ını ayarlayabilme yeteneğini (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config), başlattığı herhangi bir Node process'inde code execution ile eşdeğer kabul edin.
- Process exec işlemlerini, [Shield](https://github.com/theevilbit/Shield) tarafından `ELECTRON_RUN_AS_NODE` ve dyld injection variables için verilen alert'lerle aynı şekilde bu variables açısından monitor edin.

## References

- [1] [Node.js CLI documentation — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` ve `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

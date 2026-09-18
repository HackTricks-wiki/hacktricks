# Injection aplikacji Node.js w macOS

{{#include ../../../banners/hacktricks-training.md}}

## Przegląd

Jeśli attacker może kontrolować środowisko procesu, który ostatecznie uruchamia **Node.js** (bezpośrednio binarny plik `node` lub dowolne narzędzie CLI oparte na Node, takie jak `npm`, `npx`, `yarn`, `pnpm`, `eslint`, `tsc`, `next`, …), kilka zmiennych środowiskowych powoduje, że runtime **załaduje i wykona kontrolowany przez attackera kod JavaScript przed uruchomieniem docelowego programu**. Jest to prymityw umożliwiający wykonanie kodu, odpowiednik rodzin `PERL5OPT`/`RUBYOPT`/`_JAVA_OPTIONS` dla innych runtime'ów.

Wstępnie załadowany kod działa **w tym samym procesie**, z tym samym uid, środowiskiem, deskryptorami plików i uprawnieniami co ofiara, dlatego stanowi skuteczny wektor injection/priv-esc, gdy bardziej uprzywilejowany proces uruchamia Node z odziedziczonym lub kontrolowanym przez attackera środowiskiem.

## `NODE_OPTIONS` — `--require` (oparty na pliku)

`NODE_OPTIONS` jest analizowane tak, jakby jego zawartość była dodatkowymi flagami wiersza poleceń. `--require` (`-r`) wstępnie ładuje moduł CommonJS **przed** punktem wejścia, więc jego kod najwyższego poziomu wykona się jako pierwszy.<sup>[[1]](#references)</sup>
```bash
# Target script
echo "console.log('target script ran')" > /tmp/victim.js

# Attacker-controlled preload module
echo "require('fs').writeFileSync('/tmp/node-require-executed','x'); console.log('[require preload]')" > /tmp/preload.js

NODE_OPTIONS="--require /tmp/preload.js" node /tmp/victim.js
# [require preload]
# target script ran
```
## `NODE_OPTIONS` — `--import` z adresem URL `data:` (bez pliku)

Od **Node 20.6** `--import` akceptuje adres URL `data:text/javascript,<code>`, umożliwiając wstępne ładowanie JavaScript modułów ES **bezpośrednio, bez pliku na dysku i bez katalogu modułu**. Kod musi być **w pełni zakodowany w URL** (surowa spacja lub `#` obcina adres URL data i powoduje błąd `SyntaxError`).<sup>[[1]](#references)[[2]](#references)</sup>
```bash
# Build a fully URL-encoded data: URL payload
node -e 'const js="import(\"fs\").then(f=>f.writeFileSync(\"/tmp/node-import-executed\",\"x\"));console.log(\"[import preload]\")"; console.log("data:text/javascript,"+encodeURIComponent(js))' > /tmp/dataurl.txt

NODE_OPTIONS="--import $(cat /tmp/dataurl.txt)" node /tmp/victim.js
# [import preload]
# target script ran
```
Jest to technika wykorzystywana w chmurze, np. przez wstrzyknięcie `NODE_OPTIONS` do konfiguracji funkcji AWS Lambda (`lambda:UpdateFunctionConfiguration`, bez wymagania `iam:PassRole`) w celu uruchomienia kodu jako execution role.

> [!TIP]
> `NODE_OPTIONS` **nie może uruchamiać kodu bezpośrednio**: flagi takie jak `--eval`/`-e`, `-p` lub ścieżka do skryptu są jawnie odrzucane (`node: --eval is not allowed in NODE_OPTIONS`). Zamiast tego użyj `--require`/`--import`, aby wskazać kod.

## `NODE_OPTIONS` — custom loaders / inne flagi startowe

`NODE_OPTIONS` obsługuje również inne flagi wpływające na uruchamianie, których efektem ubocznym jest uruchomienie kodu atakującego, np. hook loadera ESM:
```bash
# Node >= 20.6 (loader hooks run in a separate thread)
NODE_OPTIONS="--import ./hooks.mjs" node app.mjs
# Older Node
NODE_OPTIONS="--experimental-loader ./hooks.mjs" node app.mjs
```
Każdy launcher oparty na Node, który uruchamia proces potomny `node`, zazwyczaj **przekazuje `NODE_OPTIONS`**, więc jednokrotne wstrzyknięcie może wpłynąć na cały toolchain (`npm run …`, `npx`, build tools, test runners, language servers).

## `NODE_REPL_EXTERNAL_MODULE`

Gdy Node uruchamia **interaktywny REPL**, ładuje moduł wskazany przez `NODE_REPL_EXTERNAL_MODULE`, wykonując jego kod najwyższego poziomu. Jest to przydatne, gdy ofiara uruchamia interaktywną powłokę `node`/`node -i` (dev tooling, maintenance consoles).<sup>[[3]](#references)</sup>
```bash
echo "require('fs').writeFileSync('/tmp/node-repl-executed','x'); module.exports={};" > /tmp/replmod.js
printf '.exit\n' | NODE_REPL_EXTERNAL_MODULE=/tmp/replmod.js node -i
ls -la /tmp/node-repl-executed
```
> [!WARNING]
> `NODE_REPL_EXTERNAL_MODULE` jest celowo **ignorowane**, gdy do uruchomienia procesu potomnego używana jest ochrona [`kDisableNodeOptionsEnv`](https://nodejs.org/api/cli.html), ale interaktywny REPL uruchomiony bezpośrednio respektuje tę zmienną.

## Electron (`ELECTRON_RUN_AS_NODE`)

Aplikacje Electron ponownie udostępniają pełne środowisko uruchomieniowe Node po uruchomieniu z **`ELECTRON_RUN_AS_NODE=1`** — w tym momencie wszystkie opisane powyżej wektory `NODE_OPTIONS` dotyczą pliku binarnego Electron, który często jest podpisany i posiada odpowiednie uprawnienia. Zobacz:

{{#ref}}
macos-electron-applications-injection.md
{{#endref}}

## Inne runtime'y JS

- **Bun** odczytuje `NODE_OPTIONS` dla zapewnienia kompatybilności i obsługuje własne `--preload` (konfigurowalne przez `bunfig.toml`).
- **Deno** nie respektuje `NODE_OPTIONS`; zamiast tego wymaga jawnych flag (`--import`, `--preload`), dlatego nie jest podatne na odziedziczone `NODE_OPTIONS`.

Zawsze potwierdzaj dokładny runtime i jego wersję, ponieważ akceptowane flagi zmieniają się między wydaniami.

## Hardening

- Usuń `NODE_OPTIONS`, `NODE_REPL_EXTERNAL_MODULE` i `ELECTRON_RUN_AS_NODE` ze środowiska przed uruchomieniem Node z bardziej uprzywilejowanego kontekstu; uruchamiaj procesy potomne z oczyszczonym środowiskiem.
- Traktuj możliwość ustawienia środowiska celu (wstrzykiwanie konfiguracji, `launchd`/`launchctl setenv`, plist/`EnvironmentVariables`, zmienne CI, konfiguracja Lambda/container) jako równoważną wykonywaniu kodu w każdym uruchamianym przez niego procesie Node.
- Monitoruj uruchamianie procesów pod kątem tych zmiennych tak samo, jak [Shield](https://github.com/theevilbit/Shield) zgłasza `ELECTRON_RUN_AS_NODE` i zmienne dy injection.

## References

- [1] [Dokumentacja Node.js CLI — `NODE_OPTIONS`, `--require`, `--import`](https://nodejs.org/api/cli.html#node_optionsoptions)
- [2] [Node.js ESM — `--import` i adresy URL `data:`](https://nodejs.org/api/esm.html#data-imports)
- [3] [Node.js REPL — `NODE_REPL_EXTERNAL_MODULE`](https://nodejs.org/api/repl.html#environment-variable-options)
{{#include ../../../banners/hacktricks-training.md}}
